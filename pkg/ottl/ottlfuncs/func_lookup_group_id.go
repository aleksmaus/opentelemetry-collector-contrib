// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ottlfuncs // import "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/ottlfuncs"

import (
	"context"
	"fmt"
	"os/user"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl"
)

type LookupGroupIDArguments[K any] struct {
	Target ottl.StringLikeGetter[K]
}

func NewLookupGroupIDFactory[K any]() ottl.Factory[K] {
	return ottl.NewFactory("LookupGroupID", &LookupGroupIDArguments[K]{}, createLookupGroupIDFunction[K])
}

func createLookupGroupIDFunction[K any](_ ottl.FunctionContext, oArgs ottl.Arguments) (ottl.ExprFunc[K], error) {
	args, ok := oArgs.(*LookupGroupIDArguments[K])

	if !ok {
		return nil, fmt.Errorf("LookupGroupIDArguments args must be of type *LookupGroupIDArguments[K]")
	}

	return lookupGroupID(args.Target), nil
}

func lookupGroupID[K any](target ottl.StringLikeGetter[K]) ottl.ExprFunc[K] {
	return func(ctx context.Context, tCtx K) (any, error) {
		gid, err := target.Get(ctx, tCtx)
		if err != nil {
			return "", err
		}
		if gid == nil {
			return "", nil
		}

		group, err := user.LookupGroupId(*gid)
		if err != nil {
			return "", fmt.Errorf("group id lookup failed, id: %v, err: %w", gid, err)
		}

		return group.Name, nil
	}
}
