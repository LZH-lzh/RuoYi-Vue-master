package com.ruoyi.vuln.service;

import java.util.List;
import com.ruoyi.vuln.domain.VulnDetectHistory;

/**
 * 漏洞扫描历史记录Service接口
 * 
 * @author ruoyi
 * @date 2022-09-25
 */
public interface IVulnDetectHistoryService 
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
     * 批量删除漏洞扫描历史记录
     * 
     * @param recordsIds 需要删除的漏洞扫描历史记录主键集合
     * @return 结果
     */
    public int deleteVulnDetectHistoryByRecordsIds(Long[] recordsIds);

    /**
     * 删除漏洞扫描历史记录信息
     * 
     * @param recordsId 漏洞扫描历史记录主键
     * @return 结果
     */
    public int deleteVulnDetectHistoryByRecordsId(Long recordsId);
}
