package oidc

import (
	"context"
	"strconv"

	"github.com/ory/herodot"
	"github.com/xen0n/go-workwx"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

type WeComOAuth2Client struct {
	oauth2.Config
	app *workwx.WorkwxApp
}

func (c *WeComOAuth2Client) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return c.Config.AuthCodeURL(state, opts...) + "#wechat_redirect"
}

func (c *WeComOAuth2Client) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	wecomToken, err := c.app.GetUserInfoByCode(code)
	if err != nil {
		return nil, err
	}

	// 企业微信没有 User 级别的 Access Token
	token := oauth2.Token{}

	return token.WithExtra(map[string]interface{}{
		"user_id": wecomToken.UserID,
	}), nil
}

type ProviderWeCom struct {
	config *Configuration
	reg    dependencies
	app    *workwx.WorkwxApp
}

func NewProviderWeCom(
	config *Configuration,
	reg dependencies,
) *ProviderWeCom {
	return &ProviderWeCom{
		config: config,
		reg:    reg,
		app:    workwx.New(config.ClientID).WithApp(config.ClientSecret, config.AgentId),
	}
}

func (w *ProviderWeCom) Config() *Configuration {
	return w.config
}

func (w *ProviderWeCom) oauth2(ctx context.Context) *WeComOAuth2Client {
	return &WeComOAuth2Client{
		Config: oauth2.Config{
			ClientID:     w.config.ClientID,
			ClientSecret: w.config.ClientSecret,
			Endpoint: oauth2.Endpoint{
				// slack's oauth v2 does not implement the oauth2 standard so we use the old version.
				// to use v2 we would need to rename the request 'scope' field to 'user_scope'.
				AuthURL:  "https://open.weixin.qq.com/connect/oauth2/authorize",
				TokenURL: "https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo",
			},
			RedirectURL: w.config.Redir(w.reg.Config(ctx).OIDCRedirectURIBase()),
			Scopes:      []string{"snsapi_base"},
		},
		app: w.app,
	}
}

func (w *ProviderWeCom) OAuth2(ctx context.Context) (OAuth2Client, error) {
	return w.oauth2(ctx), nil
}

func (w *ProviderWeCom) AuthCodeURLOptions(r ider) []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("appid", w.config.ClientID),
		oauth2.SetAuthURLParam("agentid", strconv.FormatInt(w.config.AgentId, 10)),
	}
}

func (w *ProviderWeCom) Claims(ctx context.Context, exchange *oauth2.Token) (*Claims, error) {
	identity, err := w.app.GetUser(exchange.Extra("user_id").(string))
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}

	claims := &Claims{
		Issuer:            "https://work.weixin.qq.com/",
		Subject:           identity.UserID,
		Name:              identity.Name,
		PreferredUsername: identity.UserID,
		Nickname:          identity.Name,
		Email:             identity.Email,
		EmailVerified:     true,
		Picture:           identity.QRCodeURL,
	}

	return claims, nil
}
