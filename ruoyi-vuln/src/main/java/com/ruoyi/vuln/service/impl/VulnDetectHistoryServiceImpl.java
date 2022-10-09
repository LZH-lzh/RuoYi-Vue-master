package com.ruoyi.vuln.service.impl;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.ArrayList;
import com.ruoyi.common.utils.StringUtils;
import org.springframework.transaction.annotation.Transactional;
import com.ruoyi.vuln.domain.VulnSingleAddrDetails;
import com.ruoyi.vuln.mapper.VulnDetectHistoryMapper;
import com.ruoyi.vuln.domain.VulnDetectHistory;
import com.ruoyi.vuln.service.IVulnDetectHistoryService;

/**
 * 漏洞扫描历史记录Service业务层处理
 * 
 * @author ruoyi
 * @date 2022-09-25
 */
@Service
public class VulnDetectHistoryServiceImpl implements IVulnDetectHistoryService 
{
    @Autowired
    private VulnDetectHistoryMapper vulnDetectHistoryMapper;

    /**
     * 查询漏洞扫描历史记录
     * 
     * @param recordsId 漏洞扫描历史记录主键
     * @return 漏洞扫描历史记录
     */
    @Override
    public VulnDetectHistory selectVulnDetectHistoryByRecordsId(Long recordsId)
    {
        return vulnDetectHistoryMapper.selectVulnDetectHistoryByRecordsId(recordsId);
    }

    /**
     * 查询漏洞扫描历史记录列表
     * 
     * @param vulnDetectHistory 漏洞扫描历史记录
     * @return 漏洞扫描历史记录
     */
    @Override
    public List<VulnDetectHistory> selectVulnDetectHistoryList(VulnDetectHistory vulnDetectHistory)
    {
        return vulnDetectHistoryMapper.selectVulnDetectHistoryList(vulnDetectHistory);
    }

    /**
     * 新增漏洞扫描历史记录
     * 
     * @param vulnDetectHistory 漏洞扫描历史记录
     * @return 结果
     */
    @Transactional
    @Override
    public int insertVulnDetectHistory(VulnDetectHistory vulnDetectHistory)
    {
        int rows = vulnDetectHistoryMapper.insertVulnDetectHistory(vulnDetectHistory);
        insertVulnSingleAddrDetails(vulnDetectHistory);
        return rows;
    }

    /**
     * 修改漏洞扫描历史记录
     * 
     * @param vulnDetectHistory 漏洞扫描历史记录
     * @return 结果
     */
    @Transactional
    @Override
    public int updateVulnDetectHistory(VulnDetectHistory vulnDetectHistory)
    {
        vulnDetectHistoryMapper.deleteVulnSingleAddrDetailsByRecordsId(vulnDetectHistory.getRecordsId());
        insertVulnSingleAddrDetails(vulnDetectHistory);
        return vulnDetectHistoryMapper.updateVulnDetectHistory(vulnDetectHistory);
    }

    /**
     * 批量删除漏洞扫描历史记录
     * 
     * @param recordsIds 需要删除的漏洞扫描历史记录主键
     * @return 结果
     */
    @Transactional
    @Override
    public int deleteVulnDetectHistoryByRecordsIds(Long[] recordsIds)
    {
        vulnDetectHistoryMapper.deleteVulnSingleAddrDetailsByRecordsIds(recordsIds);
        return vulnDetectHistoryMapper.deleteVulnDetectHistoryByRecordsIds(recordsIds);
    }

    /**
     * 删除漏洞扫描历史记录信息
     * 
     * @param recordsId 漏洞扫描历史记录主键
     * @return 结果
     */
    @Transactional
    @Override
    public int deleteVulnDetectHistoryByRecordsId(Long recordsId)
    {
        vulnDetectHistoryMapper.deleteVulnSingleAddrDetailsByRecordsId(recordsId);
        return vulnDetectHistoryMapper.deleteVulnDetectHistoryByRecordsId(recordsId);
    }

    /**
     * 新增单条地址扫描结果信息
     * 
     * @param vulnDetectHistory 漏洞扫描历史记录对象
     */
    public void insertVulnSingleAddrDetails(VulnDetectHistory vulnDetectHistory)
    {
        List<VulnSingleAddrDetails> vulnSingleAddrDetailsList = vulnDetectHistory.getVulnSingleAddrDetailsList();
        Long recordsId = vulnDetectHistory.getRecordsId();
        if (StringUtils.isNotNull(vulnSingleAddrDetailsList))
        {
            List<VulnSingleAddrDetails> list = new ArrayList<VulnSingleAddrDetails>();
            for (VulnSingleAddrDetails vulnSingleAddrDetails : vulnSingleAddrDetailsList)
            {
                vulnSingleAddrDetails.setRecordsId(recordsId);
                list.add(vulnSingleAddrDetails);
            }
            if (list.size() > 0)
            {
                vulnDetectHistoryMapper.batchVulnSingleAddrDetails(list);
            }
        }
    }
}
