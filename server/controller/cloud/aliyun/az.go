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

package aliyun

import (
	vpc "github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/logger"
)

func (a *Aliyun) getAZs(region model.Region) ([]model.AZ, error) {
	var retAZs []model.AZ

	log.Debug("get azs starting", logger.NewORGPrefix(a.orgID))
	request := vpc.CreateDescribeZonesRequest()
	response, err := a.getAZResponse(region.Label, request)
	if err != nil {
		log.Error(err, logger.NewORGPrefix(a.orgID))
		return retAZs, err
	}

	for _, r := range response {
		azs, _ := r.Get("Zone").Array()
		for i := range azs {
			az := r.Get("Zone").GetIndex(i)

			zoneId := az.Get("ZoneId").MustString()
			retAZ := model.AZ{
				Lcuuid:       common.GenerateUUIDByOrgID(a.orgID, a.uuidGenerate+"_"+zoneId),
				Name:         az.Get("LocalName").MustString(),
				Label:        zoneId,
				RegionLcuuid: a.getRegionLcuuid(region.Lcuuid),
			}
			retAZs = append(retAZs, retAZ)
		}
	}
	log.Debug("get azs complete", logger.NewORGPrefix(a.orgID))
	return retAZs, nil
}
