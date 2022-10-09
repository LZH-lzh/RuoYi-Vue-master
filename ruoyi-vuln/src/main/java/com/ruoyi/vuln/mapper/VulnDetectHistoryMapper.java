package com.ruoyi.vuln.mapper;

import java.util.List;
import com.ruoyi.vuln.domain.VulnDetectHistory;
import com.ruoyi.vuln.domain.VulnSingleAddrDetails;

/**
 * 漏洞扫描历史记录Mapper接口
 * 
 * @author ruoyi
 * @date 2022-09-25
 */
public interface VulnDetectHistoryMapper 
{
    /**
     * 查询漏洞扫描历史记录
     * 
     * @param recordsId 漏洞扫描历史记录主键
     * @return 漏洞扫描历史记录
     */
    public VulnDetectHistory selectVulnDetectHistoryByRecordsId(Long recordsId);

    /**
     * 查询漏洞扫描历史记录列表
     * 
     * @param vulnDetectHistory 漏洞扫描历史记录
     * @return 漏洞扫描历史记录集合
     */
    public List<VulnDetectHistory> selectVulnDetectHistoryList(VulnDetectHistory vulnDetectHistory);

    /**
     * 新增漏洞扫描历史记录
     * 
     * @param vulnDetectHistory 漏洞扫描历史记录
     * @return 结果
     */
    public int insertVulnDetectHistory(VulnDetectHistory vulnDetectHistory);

    /**
     * 修改漏洞扫描历史记录
     * 
     * @param vulnDetectHistory 漏洞扫描历史记录
     * @return 结果
     */
    public int updateVulnDetectHistory(VulnDetectHistory vulnDetectHistory);

    /**
     * 删除漏洞扫描历史记录
     * 
     * @param recordsId 漏洞扫描历史记录主键
     * @return 结果
     */
    public int deleteVulnDetectHistoryByRecordsId(Long recordsId);

    /**
     * 批量删除漏洞扫描历史记录
     * 
     * @param recordsIds 需要删除的数据主键集合
     * @return 结果
     */
    public int deleteVulnDetectHistoryByRecordsIds(Long[] recordsIds);

    /**
     * 批量删除单条地址扫描结果
     * 
     * @param recordsIds 需要删除的数据主键集合
     * @return 结果
     */
    public int deleteVulnSingleAddrDetailsByRecordsIds(Long[] recordsIds);
    
    /**
     * 批量新增单条地址扫描结果
     * 
     * @param vulnSingleAddrDetailsList 单条地址扫描结果列表
     * @return 结果
     */
    public int batchVulnSingleAddrDetails(List<VulnSingleAddrDetails> vulnSingleAddrDetailsList);
    

    /**
     * 通过漏洞扫描历史记录主键删除单条地址扫描结果信息
     * 
     * @param recordsId 漏洞扫描历史记录ID
     * @return 结果
     */
    public int deleteVulnSingleAddrDetailsByRecordsId(Long recordsId);
}
