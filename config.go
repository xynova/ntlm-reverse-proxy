package main

import (
	"net/url"
	"github.com/spf13/viper"
	"errors"
	"strings"
)

type proxyConfig struct {
	address string
	port int
	username string
	password string
	targetUrl *url.URL
	logLevel string
}



func init(){
	viper.SetDefault("targetUrl","")
	viper.SetDefault("port","8080")
	viper.SetDefault("address","localhost")
	viper.SetDefault("username","")
	viper.SetDefault("password","")
	viper.SetDefault("loglevel","info")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-","_") )
}



func parseProxyConfig() (*proxyConfig, error){
	var (
		address   	= viper.GetString("address")
		port		= viper.GetInt("port")
		username    = viper.GetString("username")
		password 	= viper.GetString("password")
		targetUrl	= viper.GetString("targetUrl")
		logLevel	= viper.GetString("logLevel")
		uri *url.URL
		err error
	)



	if len(targetUrl) == 0 {
		return nil,errors.New("targetUrl cannot be empty")
	}

	if len(username) == 0 {
		return nil,errors.New("username cannot be empty")
	}

	if len(password) == 0 {
		return nil,errors.New("password cannot be empty")
	}

	// Configure reverse proxy
	if uri, err = url.ParseRequestURI(targetUrl); err != nil {
		return nil, err
	}

	rt := proxyConfig{
		address: address,
		port:port,
		username:username,
		password:password,
		targetUrl:uri,
		logLevel:logLevel,

	}

	return &rt, nil
}