package toolbox

import (
	"context"
	"fmt"

	"github.com/godaddy/asherah/go/appencryption"
	"github.com/godaddy/asherah/go/appencryption/pkg/crypto/aead"
	"github.com/godaddy/asherah/go/appencryption/pkg/kms"
	"github.com/godaddy/asherah/go/appencryption/pkg/persistence"
	"github.com/opentracing/opentracing-go"
)

// Dencrypt a data blob using ashera.
// The jobID is used to find the appropriate ashera session to use.
func (t *Toolbox) Dencrypt(ctx context.Context, jobID string, decryptionRecord appencryption.DataRowRecord) ([]byte, error) {
	var span opentracing.Span
	span, ctx = opentracing.StartSpanFromContext(ctx, "DecryptData")
	span.LogKV("dataSizeBytes", len(decryptionRecord.Data))
	defer span.Finish()

	session, err := t.GetAsheraSession(ctx, jobID)
	if err != nil {
		span.LogKV("error", err)
		return nil, fmt.Errorf("error getting asherah session: %w", err)
	}
	out, err := session.Decrypt(decryptionRecord)
	if err != nil {
		span.LogKV("error", err)
		return nil, err
	}

	return out, nil
}

// Encrypt a data blob using ashera
// The jobID is used to find the appropriate ashera session to use.
func (t *Toolbox) Encrypt(ctx context.Context, jobID string, data []byte) (*appencryption.DataRowRecord, error) {
	var span opentracing.Span
	span, ctx = opentracing.StartSpanFromContext(ctx, "EncryptData")
	span.LogKV("dataSizeBytes", len(data))
	defer span.Finish()

	session, err := t.GetAsheraSession(ctx, jobID)
	if err != nil {
		span.LogKV("error", err)
		return nil, fmt.Errorf("error getting asherah session: %w", err)
	}
	out, err := session.Encrypt(data)
	if err != nil {
		span.LogKV("error", err)
		return nil, err
	}

	return out, nil
}

// GetAsheraSession Get the current ashera session of this tookbox, or create one if it doesn't exist
func (t *Toolbox) GetAsheraSession(ctx context.Context, jobID string) (*appencryption.Session, error) {
	// Check if we already have a session
	if asheraSession, ok := t.AsherahSessions[jobID]; ok {
		return asheraSession, nil
	}

	session, err := t.getAsheraSession(ctx, jobID)
	if err != nil {
		return nil, err
	}
	t.AsherahSessions[jobID] = session

	return t.AsherahSessions[jobID], nil
}

// getAsheraSession Performs all the setup for getting an ashera session
func (t *Toolbox) getAsheraSession(ctx context.Context, sessionID string) (*appencryption.Session, error) {
	if t.AWSSession == nil {
		return nil, ErrNoAWSSession
	}

	// Build the Metastore
	var span opentracing.Span
	span, ctx = opentracing.StartSpanFromContext(ctx, "SetUpAsheraSession")
	span.LogKV("sessionID", sessionID)
	defer span.Finish()

	// Create metastore from AWS session
	metastore := persistence.NewDynamoDBMetastore(
		t.AWSSession,
		persistence.WithDynamoDBRegionSuffix(true),
		persistence.WithTableName(t.AsherahDBTableName),
	)

	// Create a map of region and ARN pairs that will all be used when creating a System Key
	// First if the regionARN is blank, look it up in SSM
	if t.AsherahRegionARN == "" {
		// Look up the ARN in aws SSM (parameter store)
		kmsKey, err := t.GetFromParameterStore(ctx, asherahKMSKeyParameterName, false)
		if err != nil {
			return nil, fmt.Errorf("error getting ARN of KMS Key: %w", err)
		}
		t.AsherahRegionARN = *kmsKey.Value
	}
	regionArnMap := map[string]string{
		t.AsherahRegion: t.AsherahRegionARN,
	}

	// Use AES/GCM encryption
	crypto := aead.NewAES256GCM()
	// Build the Key Management Service using the region dictionary and your preferred (usually current) region
	keyManagementService, err := kms.NewAWS(crypto, *t.AWSSession.Config.Region, regionArnMap)
	if err != nil {
		return nil, fmt.Errorf("error creating aws key management service: %w", err)
	}

	// Create a session factory
	sessionFactory := appencryption.NewSessionFactory(
		&appencryption.Config{
			Service: "ThreatAPI",
			Product: "Threat Research",
			Policy:  appencryption.NewCryptoPolicy(),
		},
		metastore,
		keyManagementService,
		crypto,
	)

	session, err := sessionFactory.GetSession(sessionID)
	if err != nil {
		return nil, fmt.Errorf("error creating session: %w", err)
	}

	return session, nil
}
