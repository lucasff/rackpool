package integration

import (
	"context"
	"net/http"

	"mediapool/internal/auth"
	"mediapool/internal/merkle"
	"mediapool/internal/proto"
	"mediapool/internal/transfer"
)

// Raw requests an attacker can make without going through the client.

func transferPut(ctx context.Context, addr, seg string, idx int, data []byte, t *proto.Ticket) error {
	return transfer.PutShard(ctx, http.DefaultClient, addr, seg, idx, data, nil, t)
}

func transferPutProof(ctx context.Context, addr, seg string, idx int, data []byte, proof []merkle.Hash, t *proto.Ticket) error {
	return transfer.PutShard(ctx, http.DefaultClient, addr, seg, idx, data, proof, t)
}

func postJSON(ctx context.Context, id *auth.Identity, url string, in, out any) error {
	return transfer.PostJSON(ctx, http.DefaultClient, id, url, in, out)
}
