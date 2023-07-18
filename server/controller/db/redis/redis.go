/*
 * Copyright (c) 2023 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package redis

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/go-redis/redis/v9"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("db.redis")
var (
	redisClientOnce sync.Once
	RedisDB         *RedisClient
)

type RedisConfig struct {
	ResourceAPIDatabase       int      `default:"1" yaml:"resource_api_database"`
	ResourceAPIExpireInterval int      `default:"3600" yaml:"resource_api_expire_interval"`
	DimensionResourceDatabase int      `default:"2" yaml:"dimension_resource_database"`
	Host                      []string `default:"" yaml:"host"` // TODO add default value
	Port                      uint32   `default:"6379" yaml:"port"`
	Password                  string   `default:"deepflow" yaml:"password"`
	TimeOut                   uint32   `default:"30" yaml:"timeout"`
	Enabled                   bool     `default:"false" yaml:"enabled"`
	ClusterEnabled            bool     `default:"false" yaml:"cluster_enabled"`
}

func GetClient() *RedisClient {
	return RedisDB
}

type RedisClient struct {
	ResourceAPI       redis.UniversalClient
	DimensionResource redis.UniversalClient
	Config            *config.RedisConfig
}

func generateAddrs(cfg config.RedisConfig) []string {
	var addrs []string
	for i := range cfg.Host {
		addrs = append(addrs, fmt.Sprintf("%s:%d", cfg.Host[i], cfg.Port))
	}
	return addrs
}

func generateSimpleAddr(cfg config.RedisConfig) string {
	return generateAddrs(cfg)[0]
}

func createSimpleClient(cfg config.RedisConfig, database int) redis.UniversalClient {
	addr := generateSimpleAddr(cfg)
	log.Infof("redis addr: %v", addr)
	return redis.NewClient(&redis.Options{
		Addr:        addr,
		Password:    cfg.Password,
		DB:          database,
		DialTimeout: time.Duration(cfg.TimeOut) * time.Second,
	})
}

func generateClusterAddrs(cfg config.RedisConfig) []string {
	return generateAddrs(cfg)
}

func createClusterClient(cfg config.RedisConfig) redis.UniversalClient {
	addrs := generateClusterAddrs(cfg)
	log.Infof("redis addrs: %v", addrs)
	return redis.NewClusterClient(&redis.ClusterOptions{
		Addrs:       addrs,
		Password:    cfg.Password,
		DialTimeout: time.Duration(cfg.TimeOut) * time.Second,
	})
}

func createUniversalRedisClient(cfg config.RedisConfig, database int) redis.UniversalClient {
	if cfg.ClusterEnabled {
		return createClusterClient(cfg)
	} else {
		return createSimpleClient(cfg, database)
	}
}

func InitRedis(cfg config.RedisConfig, ctx context.Context) (err error) { // TODO ctx as first param
	redisClientOnce.Do(func() {
		RedisDB = &RedisClient{
			ResourceAPI:       createUniversalRedisClient(cfg, cfg.ResourceAPIDatabase),
			DimensionResource: createUniversalRedisClient(cfg, cfg.DimensionResourceDatabase),
		}
		_, err = RedisDB.ResourceAPI.Ping(ctx).Result()
		if err != nil {
			return
		}
		_, err = RedisDB.DimensionResource.Ping(ctx).Result()
		return
	})
	return
}
