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

package decoder

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/deepflowio/deepflow/server/ingester/profile/common"
	"github.com/deepflowio/deepflow/server/ingester/profile/dbwriter"
	"github.com/deepflowio/deepflow/server/libs/flow-metrics/pb"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/utils"
	"github.com/klauspost/compress/zstd"
	"github.com/pyroscope-io/pyroscope/pkg/storage"
)

type Parser struct {
	profileName   string
	vtapID        uint16
	orgId, teamId uint16
	IP            net.IP
	podID         uint32

	// profileWriter.Write
	callBack                   func([]interface{})
	writeItemCache             []interface{}
	offCpuSplittingGranularity int

	platformData    *grpc.PlatformInfoTable
	inTimestamp     time.Time
	compressionAlgo string
	*observer
	*processTracer
	*Counter
}

type processTracer struct {
	pid       uint32
	stime     int64
	eventType string
	value     uint32
}

// implement storage.Putter
// triggered by input.Profile.Parse
func (p *Parser) Put(ctx context.Context, i *storage.PutInput) error {
	i.Val.IterateStacks(func(name string, self uint64, stack []string) {
		for i, j := 0, len(stack)-1; i < j; i, j = i+1, j-1 {
			stack[i], stack[j] = stack[j], stack[i]
		}
		inProcesses := p.stackToInProcess(i, stack, self)
		p.callBack(inProcesses)
	})
	return nil
}

// implement storage.MetricsExporter
// triggered by input.Profile.Parse
func (p *Parser) Evaluate(i *storage.PutInput) (storage.SampleObserver, bool) {
	return p.observer, true
}

func (p *Parser) stackToInProcess(input *storage.PutInput, stack []string, value uint64) []interface{} { // []*dbwriter.InProcessProfile
	labels := input.Key.Labels()
	tagNames := make([]string, 0, len(labels))
	tagValues := make([]string, 0, len(labels))
	for k, v := range labels {
		tagNames = append(tagNames, k)
		tagValues = append(tagValues, v)
	}
	ret := dbwriter.AcquireInProcess()
	var ip4 uint32
	if ip := p.IP.To4(); ip != nil {
		ip4 = utils.IpToUint32(ip)
		ret.IsIPv4 = true
	}
	if ret.IsIPv4 {
		ret.IP4 = ip4
	} else {
		ret.IP6 = p.IP
	}

	var pid uint32
	var stime int64
	var eventType string

	onelineStack := strings.Join(stack, ";")
	atomic.AddInt64(&p.Counter.UncompressSize, int64(len(onelineStack)))

	location := compress(onelineStack, p.compressionAlgo)
	atomic.AddInt64(&p.Counter.CompressedSize, int64(len(location)))

	profileValueUs := int64(value)
	if p.processTracer != nil {
		profileValueUs = int64(p.value)
		pid = p.processTracer.pid
		stime = p.processTracer.stime
		eventType = p.processTracer.eventType
	} else {
		eventType = strings.TrimPrefix(input.Key.AppName(), fmt.Sprintf("%s.", p.profileName))
	}
	ret.FillProfile(input,
		p.platformData,
		p.vtapID,
		p.orgId, p.teamId,
		p.podID,
		p.profileName,
		eventType,
		location,
		p.compressionAlgo,
		profileValueUs,
		p.inTimestamp,
		spyMap[input.SpyName],
		pid,
		stime,
		tagNames,
		tagValues)

	granularityUs := int64(p.offCpuSplittingGranularity) * int64(time.Second/time.Microsecond)
	if ret.ProfileEventType == pb.ProfileEventType_EbpfOffCpu.String() &&
		p.offCpuSplittingGranularity > 0 &&
		profileValueUs > granularityUs {

		splitCount := profileValueUs / granularityUs
		if profileValueUs%granularityUs > 0 {
			splitCount++
		}
		for i := int64(0); i < splitCount-1; i++ {
			splitItem := ret.Clone()
			splitItem.Time = splitItem.Time + uint32(i)*uint32(p.offCpuSplittingGranularity)
			splitItem.ProfileCreateTimestamp = splitItem.ProfileCreateTimestamp + i*granularityUs
			splitItem.ProfileValue = granularityUs
			p.writeItemCache = append(p.writeItemCache, splitItem)
		}
		// test
		p.writeItemCache = append(p.writeItemCache, ret)
		ret = ret.Clone()
		// add ret for last split item
		ret.Time = ret.Time + uint32(splitCount-1)*uint32(p.offCpuSplittingGranularity)
		ret.ProfileCreateTimestamp = ret.ProfileCreateTimestamp + (splitCount-1)*granularityUs
		ret.ProfileValue = profileValueUs - (splitCount-1)*granularityUs
		p.writeItemCache = append(p.writeItemCache, ret)
	} else {
		p.writeItemCache = append(p.writeItemCache, ret)
	}

	return p.writeItemCache
}

type observer struct {
	// FIXME: not implemented, used it for `func.Evaluate`
}

func (s *observer) Observe(k []byte, v int) {
	// FIXME: generate some metrics
	// e.g.: convert profile application & profile labels to prometheus series
}

func compress(src string, algo string) string {
	switch algo {
	case "":
		return src
	case "zstd":
		dst := make([]byte, 0, len(src))
		result, err := common.ZstdCompress(dst, []byte(src), zstd.SpeedDefault)
		if err != nil {
			log.Errorf("compress error: %v", err)
			return src
		}
		// str after compressed and algo
		return string(result)
	default:
		return src
	}
}

func deCompress(str []byte, algo string) string {
	switch algo {
	case "":
		return string(str)
	case "zstd":
		dst := make([]byte, 0, len(str))
		result, err := common.ZstdDecompress(dst, str)
		if err != nil {
			log.Errorf("decompress error: %v", err)
			return ""
		}
		return string(result)
	default:
		return string(str)
	}
}
