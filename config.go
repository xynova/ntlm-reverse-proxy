package main

import (
	"fmt"
	"net/url"
	"github.com/spf13/viper"
	"errors"
	"os"
	"strings"
)

type proxyConfig struct {
	address string
	port int
	username string
	password string
	targetUrl *url.URL
	verboseLogs bool
	tlsCertFile string
	tlsKeyFile string
}



func init(){
	viper.SetDefault("tlsCert","")
	viper.SetDefault("tlsKey","")
	viper.SetDefault("targetUrl","")
	viper.SetDefault("port","8080")
	viper.SetDefault("address","localhost")
	viper.SetDefault("username","")
	viper.SetDefault("password","")
	viper.SetDefault("debug","false")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-","_") )
}



func parseProxyConfig() (*proxyConfig, error){
	var (
		address   		= viper.GetString("address")
		port			= viper.GetInt("port")
		username    	= viper.GetString("username")
		password 		= viper.GetString("password")
		targetUrl		= viper.GetString("targetUrl")
		verboseLogs		= viper.GetBool("debug")
		tlsCertFile   	= viper.GetString("tlsCert")
		tlsKeyFile   	= viper.GetString("tlsKey")
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


	if _, err := os.Stat(tlsKeyFile);len(tlsKeyFile) > 0 && os.IsNotExist(err) {
		return nil,fmt.Errorf("The file %s does not exist",tlsKeyFile)
	}

	if _, err := os.Stat(tlsCertFile);len(tlsCertFile) > 0 && os.IsNotExist(err) {
		return nil,fmt.Errorf("The file %s does not exist",tlsCertFile)
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
		verboseLogs:verboseLogs,
		tlsCertFile:tlsCertFile,
		tlsKeyFile:tlsKeyFile,
	}

	return &rt, nil
}
