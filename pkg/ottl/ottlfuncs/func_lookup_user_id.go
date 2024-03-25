// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ottlfuncs // import "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/ottlfuncs"

import (
	"context"
	"fmt"
	"os/user"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl"
)

type LookupUserIDArguments[K any] struct {
	Target ottl.StringLikeGetter[K]
}

func NewLookupUserIDFactory[K any]() ottl.Factory[K] {
	return ottl.NewFactory("LookupUserID", &LookupUserIDArguments[K]{}, createLookupUserIDFunction[K])
}

func createLookupUserIDFunction[K any](_ ottl.FunctionContext, oArgs ottl.Arguments) (ottl.ExprFunc[K], error) {
	args, ok := oArgs.(*LookupUserIDArguments[K])

	if !ok {
		return nil, fmt.Errorf("LookupUserIDArguments args must be of type *LookupUserIDArguments[K]")
	}

	return lookupUserID(args.Target), nil
}

func lookupUserID[K any](target ottl.StringLikeGetter[K]) ottl.ExprFunc[K] {
	return func(ctx context.Context, tCtx K) (any, error) {
		sid, err := target.Get(ctx, tCtx)
		if err != nil {
			return "", err
		}
		if sid == nil {
			return "", nil
		}

		user, err := user.LookupId(*sid)
		if err != nil {
			return "", fmt.Errorf("user id lookup failed, id: %v, err: %w", sid, err)
		}

		return user.Username, nil
	}
}
