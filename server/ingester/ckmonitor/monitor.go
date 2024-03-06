/*
 * Copyright (c) 2024 Yunshan Networks
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

package ckmonitor

import (
	"fmt"
	"strings"
	"time"

	logging "github.com/op/go-logging"

	"database/sql"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("monitor")

const (
	EVENT_QUERY                = "Query"
	EVENT_SELECT_QUERY         = "SelectQuery"
	EVENT_INSERT_QUERY         = "InsertQuery"
	EVENT_QUERY_CACHE_HITS     = "QueryCacheHits"
	EVENT_QUERY_CACHE_MISSES   = "QueryCacheMissess"
	EVENT_QUERY_TIME_MS        = "QueryTimeMicroseconds"
	EVENT_SELECT_QUERY_TIME_MS = "SelectQueryTimeMicroseconds"
	EVENT_INSERT_QUERY_TIME_MS = "InsertQueryTimeMicroseconds"
)

type Monitor struct {
	cfg           *config.Config
	checkInterval int

	Conns              common.DBs
	Addrs              []string
	eventMonitors      []*EventMonitor
	username, password string
	exit               bool
}

type EventMonitor struct {
	addr, username, password string
	conn                     *sql.DB
	current, last            EventCounter
	utils.Closable
}

type EventCounter struct {
	Query             uint64  `statsd:"query"`
	SelectQuery       uint64  `statsd:"select-query"`
	InsertQuery       uint64  `statsd:"insert-query"`
	QueryCacheHits    uint64  `statsd:"query-cache-hits"`
	QueryCacheMisses  uint64  `statsd:"query-cache-misses"`
	QueryHitPercent   float64 `statsd:"query-hit-percent"`
	QueryTimeMs       uint64  `statsd:"query-time-ms"`
	SelectQueryTimeMs uint64  `statsd:"select-query-time-ms"`
	InsertQueryTimeMs uint64  `statsd:"insert-query-time-ms"`
}

func (e *EventMonitor) getCurrentCounter() error {
	if e.conn == nil {
		conn, err := common.NewCKConnection(e.addr, e.username, e.password)
		if err != nil {
			return err
		}
		e.conn = conn
	}
	rows, err := e.conn.Query(
		fmt.Sprintf("SELECT event,value FROM system.events where event in ('%s','%s','%s','%s','%s','%s','%s','%s')",
			EVENT_QUERY, EVENT_SELECT_QUERY, EVENT_INSERT_QUERY, EVENT_QUERY_CACHE_HITS, EVENT_QUERY_CACHE_MISSES, EVENT_QUERY_TIME_MS, EVENT_SELECT_QUERY_TIME_MS, EVENT_INSERT_QUERY_TIME_MS))
	if err != nil {
		log.Warningf("get ck event failed: %s", err)
		return err
	}

	var event string
	var value uint64
	for rows.Next() {
		err := rows.Scan(&event, &value)
		if err != nil {
			log.Warningf("get event failed: %s", err)
			return err
		}
		switch event {
		case EVENT_QUERY:
			e.current.Query = value
		case EVENT_SELECT_QUERY:
			e.current.SelectQuery = value
		case EVENT_INSERT_QUERY:
			e.current.InsertQuery = value
		case EVENT_QUERY_CACHE_HITS:
			e.current.QueryCacheHits = value
		case EVENT_QUERY_CACHE_MISSES:
			e.current.QueryCacheMisses = value
		case EVENT_QUERY_TIME_MS:
			e.current.QueryTimeMs = value
		case EVENT_SELECT_QUERY_TIME_MS:
			e.current.SelectQueryTimeMs = value
		case EVENT_INSERT_QUERY_TIME_MS:
			e.current.InsertQueryTimeMs = value
		}
	}
	return nil
}

func (e *EventMonitor) GetCounter() interface{} {
	if err := e.getCurrentCounter(); err != nil {
		return &EventCounter{}
	}
	counter := &EventCounter{
		Query:             e.current.Query - e.last.Query,
		SelectQuery:       e.current.SelectQuery - e.last.SelectQuery,
		InsertQuery:       e.current.InsertQuery - e.last.InsertQuery,
		QueryCacheHits:    e.current.QueryCacheHits - e.last.QueryCacheHits,
		QueryCacheMisses:  e.current.QueryCacheMisses - e.last.QueryCacheMisses,
		QueryTimeMs:       e.current.QueryTimeMs - e.last.QueryTimeMs,
		SelectQueryTimeMs: e.current.SelectQueryTimeMs - e.last.SelectQueryTimeMs,
		InsertQueryTimeMs: e.current.InsertQueryTimeMs - e.last.InsertQueryTimeMs,
	}
	if counter.SelectQuery > 0 {
		counter.QueryHitPercent = float64(counter.QueryCacheHits) / float64(counter.SelectQuery)
	}
	e.last, e.current = e.current, EventCounter{}
	return counter
}

type DiskInfo struct {
	name, path                                      string
	freeSpace, totalSpace, keepFreeSpace, usedSpace uint64
}

type Partition struct {
	partition, database, table string
	minTime, maxTime           time.Time
	rows, bytesOnDisk          uint64
}

func NewCKMonitor(cfg *config.Config) (*Monitor, error) {
	m := &Monitor{
		cfg:           cfg,
		checkInterval: cfg.CKDiskMonitor.CheckInterval,
		Addrs:         cfg.CKDB.ActualAddrs,
		username:      cfg.CKDBAuth.Username,
		password:      cfg.CKDBAuth.Password,
	}
	var err error
	m.Conns, err = common.NewCKConnections(m.Addrs, m.username, m.password)
	if err != nil {
		return nil, err
	}

	m.eventMonitors = make([]*EventMonitor, len(m.Addrs))
	for i, addr := range m.Addrs {
		m.eventMonitors[i] = &EventMonitor{addr: addr, username: m.username, password: m.password}
		common.RegisterCountableForIngester("monitor_event", m.eventMonitors[i], stats.OptionStatTags{"ck-addr": addr})
	}

	return m, nil
}

// 如果clickhouse重启等，需要自动更新连接
func (m *Monitor) updateConnections() {
	if len(m.Addrs) == 0 {
		return
	}

	var err error
	for i, connect := range m.Conns {
		if connect == nil || connect.Ping() != nil {
			if connect != nil {
				connect.Close()
			}
			m.Conns[i], err = common.NewCKConnection(m.Addrs[i], m.username, m.password)
			if err != nil {
				log.Warning(err)
			}
		}
	}
}

func (m *Monitor) getDiskInfos(connect *sql.DB) ([]*DiskInfo, error) {
	rows, err := connect.Query("SELECT name,path,free_space,total_space,keep_free_space FROM system.disks")
	if err != nil {
		return nil, err
	}

	diskInfos := []*DiskInfo{}
	for rows.Next() {
		var (
			name, path                           string
			freeSpace, totalSpace, keepFreeSpace uint64
		)
		err := rows.Scan(&name, &path, &freeSpace, &totalSpace, &keepFreeSpace)
		if err != nil {
			return nil, nil
		}
		log.Debugf("name: %s, path: %s, freeSpace: %d, totalSpace: %d, keepFreeSpace: %d", name, path, freeSpace, totalSpace, keepFreeSpace)
		for _, cleans := range m.cfg.CKDiskMonitor.DiskCleanups {
			diskPrefix := cleans.DiskNamePrefix
			if strings.HasPrefix(name, diskPrefix) {
				usedSpace := totalSpace - freeSpace
				diskInfos = append(diskInfos, &DiskInfo{name, path, freeSpace, totalSpace, keepFreeSpace, usedSpace})
			}
		}
	}
	if len(diskInfos) == 0 {
		diskPrefixs := ""
		for _, cleans := range m.cfg.CKDiskMonitor.DiskCleanups {
			diskPrefixs += cleans.DiskNamePrefix + ","
		}
		return nil, fmt.Errorf("can not find any deepflow data disk like '%s'", diskPrefixs)
	}
	return diskInfos, nil
}

func (m *Monitor) getDiskCleanupConfig(diskName string) *config.DiskCleanup {
	for i, c := range m.cfg.CKDiskMonitor.DiskCleanups {
		if strings.HasPrefix(diskName, c.DiskNamePrefix) {
			return &m.cfg.CKDiskMonitor.DiskCleanups[i]
		}
	}
	return nil
}

func (m *Monitor) isDiskNeedClean(diskInfo *DiskInfo) bool {
	if diskInfo.totalSpace == 0 {
		return false
	}
	cleanCfg := m.getDiskCleanupConfig(diskInfo.name)
	if cleanCfg == nil {
		return false
	}

	usage := (diskInfo.usedSpace*100 + diskInfo.totalSpace - 1) / diskInfo.totalSpace
	if usage > uint64(cleanCfg.UsedPercent) && diskInfo.freeSpace < uint64(cleanCfg.FreeSpace)<<30 {
		log.Infof("disk usage is over %d%. disk name: %s, path: %s, total space: %d, free space: %d, usage: %d",
			cleanCfg.UsedPercent, diskInfo.name, diskInfo.path, diskInfo.totalSpace, diskInfo.freeSpace, usage)
		return true
	} else if cleanCfg.UsedSpace > 0 && diskInfo.usedSpace >= uint64(cleanCfg.UsedSpace)<<30 {
		log.Infof("disk used space is over %dG, disk name: %s, path: %s, total space: %d, free space: %d, usage: %d, usedSpace: %d.",
			cleanCfg.UsedSpace, diskInfo.name, diskInfo.path, diskInfo.totalSpace, diskInfo.freeSpace, usage, diskInfo.usedSpace)
		return true
	}
	return false
}

// 当所有磁盘都要满足清理条件时，才清理数据
func (m *Monitor) isDisksNeedClean(diskInfo *DiskInfo) bool {
	if !m.isDiskNeedClean(diskInfo) {
		return false
	}
	log.Warningf("disk free space is not enough, will do drop or move partitions.")
	return true
}

func (m *Monitor) isPriorityDrop(database, table string) bool {
	for _, priorityDrop := range m.cfg.CKDiskMonitor.PriorityDrops {
		if database == priorityDrop.Database {
			if priorityDrop.TablesContain == "" {
				return true
			}
			if strings.Contains(table, priorityDrop.TablesContain) {
				return true
			}
		}
	}
	return false
}

func (m *Monitor) getMinPartitions(connect *sql.DB, diskInfo *DiskInfo) ([]Partition, error) {
	sql := fmt.Sprintf("SELECT min(partition),count(distinct partition),database,table,min(min_time),max(max_time),sum(rows),sum(bytes_on_disk) FROM system.parts WHERE disk_name='%s' and active=1 GROUP BY database,table ORDER BY database,table ASC",
		diskInfo.name)
	rows, err := connect.Query(sql)
	if err != nil {
		return nil, err
	}
	partitions, partitionsPriorityDrop := []Partition{}, []Partition{}
	for rows.Next() {
		var (
			partition, database, table   string
			minTime, maxTime             time.Time
			rowCount, bytesOnDisk, count uint64
		)
		err := rows.Scan(&partition, &count, &database, &table, &minTime, &maxTime, &rowCount, &bytesOnDisk)
		if err != nil {
			return nil, err
		}
		log.Debugf("partition: %s, count: %d, database: %s, table: %s, minTime: %s, maxTime: %s, rows: %d, bytesOnDisk: %d", partition, count, database, table, minTime, maxTime, rowCount, bytesOnDisk)
		// 只删除partition数量2个以上的partition中最小的一个
		if count > 1 && m.isPriorityDrop(database, table) {
			partition := Partition{partition, database, table, minTime, maxTime, rowCount, bytesOnDisk}
			partitions = append(partitions, partition)
			partitionsPriorityDrop = append(partitionsPriorityDrop, partition)
		}
	}
	if len(partitionsPriorityDrop) > 0 {
		return partitionsPriorityDrop, nil
	}
	return partitions, nil
}

func (m *Monitor) dropMinPartitions(connect *sql.DB, diskInfo *DiskInfo) error {
	partitions, err := m.getMinPartitions(connect, diskInfo)
	if err != nil {
		return err
	}

	for _, p := range partitions {
		sql := fmt.Sprintf("ALTER TABLE %s.`%s` DROP PARTITION '%s'", p.database, p.table, p.partition)
		log.Warningf("drop partition: %s, database: %s, table: %s, minTime: %s, maxTime: %s, rows: %d, bytesOnDisk: %d", p.partition, p.database, p.table, p.minTime, p.maxTime, p.rows, p.bytesOnDisk)
		_, err := connect.Exec(sql)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Monitor) moveMinPartitions(connect *sql.DB, diskInfo *DiskInfo) error {
	partitions, err := m.getMinPartitions(connect, diskInfo)
	if err != nil {
		return err
	}
	for _, p := range partitions {
		sql := fmt.Sprintf("ALTER TABLE %s.`%s` MOVE PARTITION '%s' TO %s '%s'", p.database, p.table, p.partition, m.cfg.ColdStorage.ColdDisk.Type, m.cfg.ColdStorage.ColdDisk.Name)
		log.Warningf("move partition: %s, database: %s, table: %s, minTime: %s, maxTime: %s, rows: %d, bytesOnDisk: %d", p.partition, p.database, p.table, p.minTime, p.maxTime, p.rows, p.bytesOnDisk)
		_, err := connect.Exec(sql)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Monitor) Start() {
	go m.start()
}

func (m *Monitor) start() {
	counter := 0
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for !m.exit {
		<-ticker.C
		counter++
		if counter%m.checkInterval != 0 {
			continue
		}

		m.updateConnections()
		for _, connect := range m.Conns {
			if connect == nil {
				continue
			}
			diskInfos, err := m.getDiskInfos(connect)
			if err != nil {
				log.Warning(err)
				continue
			}
			for _, diskInfo := range diskInfos {
				if m.isDisksNeedClean(diskInfo) {
					if err := m.dropMinPartitions(connect, diskInfo); err != nil {
						log.Warning("drop partition failed.", err)
					}
				}
			}
		}
	}
}

func (m *Monitor) Close() error {
	m.exit = true
	return nil
}
