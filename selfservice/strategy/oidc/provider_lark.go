package oidc

import (
	"context"
	"time"

	"github.com/ory/herodot"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	"github.com/chyroc/lark"
)

type LarkOAuth2Client struct {
	oauth2.Config
	cli *lark.Lark
}

func (c *LarkOAuth2Client) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	larkToken, _, err := c.cli.Auth.GetAccessToken(ctx, &lark.GetAccessTokenReq{
		GrantType: "authorization_code",
		Code:      code,
	})
	if err != nil {
		return nil, err
	}

	token := oauth2.Token{
		AccessToken:  larkToken.AccessToken,
		TokenType:    larkToken.TokenType,
		RefreshToken: larkToken.RefreshToken,
		Expiry:       time.Unix(larkToken.ExpiresIn, 0),
	}

	return token.WithExtra(map[string]interface{}{
		"union_id": larkToken.UnionID,
	}), nil
}

type ProviderLark struct {
	config *Configuration
	reg    dependencies
	cli    *lark.Lark
}

func NewProviderLark(
	config *Configuration,
	reg dependencies,
) *ProviderLark {
	return &ProviderLark{
		config: config,
		reg:    reg,
		cli:    lark.New(lark.WithAppCredential(config.ClientID, config.ClientSecret)),
	}
}

func (l *ProviderLark) Config() *Configuration {
	return l.config
}

func (l *ProviderLark) oauth2(ctx context.Context) *LarkOAuth2Client {
	return &LarkOAuth2Client{
		Config: oauth2.Config{
			ClientID:     l.config.ClientID,
			ClientSecret: l.config.ClientSecret,
			Endpoint: oauth2.Endpoint{
				// slack's oauth v2 does not implement the oauth2 standard so we use the old version.
				// to use v2 we would need to rename the request 'scope' field to 'user_scope'.
				AuthURL:  "https://open.feishu.cn/open-apis/authen/v1/index",
				TokenURL: "https://open.feishu.cn/open-apis/authen/v1/access_token",
			},
			RedirectURL: l.config.Redir(l.reg.Config(ctx).OIDCRedirectURIBase()),
			Scopes:      l.config.Scope,
		},
		cli: l.cli,
	}
}

func (l *ProviderLark) OAuth2(ctx context.Context) (OAuth2Client, error) {
	return l.oauth2(ctx), nil
}

func (l *ProviderLark) AuthCodeURLOptions(r ider) []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("app_id", l.config.ClientID),
	}
}

func (l *ProviderLark) Claims(ctx context.Context, exchange *oauth2.Token) (*Claims, error) {
	identity, _, err := l.cli.Contact.GetUser(ctx, &lark.GetUserReq{
		UserIDType: lark.IDTypePtr(lark.IDTypeUnionID),
		UserID:     exchange.Extra("union_id").(string),
	})
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}

	claims := &Claims{
		Issuer:            "https://open.feishu.cn/",
		Subject:           identity.User.EmployeeNo,
		Name:              identity.User.Name,
		PreferredUsername: identity.User.EmployeeNo,
		Nickname:          identity.User.Name,
		Email:             identity.User.Email,
		EmailVerified:     true,
		Picture:           identity.User.Avatar.AvatarOrigin,
	}

	return claims, nil
}
