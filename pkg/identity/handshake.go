package identity

import (
	"crypto/sha256"

	"github.com/slipe-fun/skid-v3/internal/crypto"
)

type EncryptedSyncKey struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
}

type HandshakePayload struct {
	ReceiverCiphertext []byte `json:"receiver_ciphertext"`
	SenderCiphertext   []byte `json:"sender_ciphertext"`
	EncryptedSyncKey   EncryptedSyncKey
}

func InitiateKeyExchange(sender *User, senderSecretKeys *SecretKeys, receiver *User) (*HandshakePayload, []byte, error) {
	var (
		senderMlKemCiphertext     []byte
		senderMlKemSharedSecret   []byte
		receiverMlKemCiphertext   []byte
		receiverMlKemSharedSecret []byte
		ecdhSharedSecret          []byte
		syncMaterial              []byte
		syncKey                   []byte
		syncAAD                   []byte
		syncKeyCiphertext         []byte
		syncKeyNonce              []byte
		material                  []byte
		rootKey                   []byte
		chatKey                   []byte
		err                       error
	)

	defer func() {
		crypto.Zero(senderMlKemSharedSecret)
		crypto.Zero(receiverMlKemSharedSecret)
		crypto.Zero(ecdhSharedSecret)

		crypto.Zero(syncMaterial)
		crypto.Zero(material)

		crypto.Zero(syncKey)
		crypto.Zero(rootKey)
	}()

	senderMlKemCiphertext, senderMlKemSharedSecret, err = crypto.EncapsulateMLKEM(sender.PublicKeys.MlKem768)
	if err != nil {
		return nil, nil, err
	}

	receiverMlKemCiphertext, receiverMlKemSharedSecret, err = crypto.EncapsulateMLKEM(receiver.PublicKeys.MlKem768)
	if err != nil {
		return nil, nil, err
	}

	ecdhSharedSecret, err = crypto.DeriveECDHSharedSecret(senderSecretKeys.X448, receiver.PublicKeys.X448)
	if err != nil {
		return nil, nil, err
	}

	contextData := crypto.ConcatBytes(
		[]byte(sender.ID),
		[]byte(receiver.ID),
		sender.PublicKeys.X448,
		receiver.PublicKeys.X448,
		sender.PublicKeys.MlKem768,
		receiver.PublicKeys.MlKem768,
		senderMlKemCiphertext,
		receiverMlKemCiphertext,
	)

	sessionID := sha256.Sum256(contextData)

	syncMaterial = crypto.ConcatBytes(senderMlKemSharedSecret, ecdhSharedSecret)
	syncKey, err = crypto.HKDF(syncMaterial, sessionID[:], "skid:v3:sync_key", 32)
	if err != nil {
		return nil, nil, err
	}

	syncAAD = crypto.BuildAAD("sync_material",
		sessionID[:],
		[]byte(sender.ID),
		[]byte(receiver.ID),
		senderMlKemCiphertext,
		receiverMlKemCiphertext,
	)

	syncKeyCiphertext, syncKeyNonce, err = crypto.Encrypt(syncKey, receiverMlKemSharedSecret, syncAAD)
	if err != nil {
		return nil, nil, err
	}

	material = crypto.ConcatBytes(receiverMlKemSharedSecret, ecdhSharedSecret)

	rootKey, err = crypto.HKDF(material, sessionID[:], "skid:v3:root_key", 32)
	if err != nil {
		return nil, nil, err
	}

	chatKey, err = crypto.HKDF(rootKey, sessionID[:], "skid:v3:chat_key", 32)
	if err != nil {
		return nil, nil, err
	}

	return &HandshakePayload{
		SenderCiphertext:   senderMlKemCiphertext,
		ReceiverCiphertext: receiverMlKemCiphertext,
		EncryptedSyncKey: EncryptedSyncKey{
			Ciphertext: syncKeyCiphertext,
			Nonce:      syncKeyNonce,
		},
	}, chatKey, nil
}
