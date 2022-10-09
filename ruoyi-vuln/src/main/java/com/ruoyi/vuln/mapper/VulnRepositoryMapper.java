package com.ruoyi.vuln.mapper;

import java.util.List;
import com.ruoyi.vuln.domain.VulnRepository;

/**
 * 漏洞库Mapper接口
 * 
 * @author IPv6ScanGroup
 * @date 2022-10-05
 */
public interface VulnRepositoryMapper 
{
    /**
     * 查询漏洞库
     * 
     * @param scriptId 漏洞库主键
     * @return 漏洞库
     */
    public VulnRepository selectVulnRepositoryByScriptId(Long scriptId);

    /**
     * 查询漏洞库列表
     * 
     * @param vulnRepository 漏洞库
     * @return 漏洞库集合
     */
    public List<VulnRepository> selectVulnRepositoryList(VulnRepository vulnRepository);

    /**
     * 新增漏洞库
     * 
     * @param vulnRepository 漏洞库
     * @return 结果
     */
    public int insertVulnRepository(VulnRepository vulnRepository);

    /**
     * 修改漏洞库
     * 
     * @param vulnRepository 漏洞库
     * @return 结果
     */
    public int updateVulnRepository(VulnRepository vulnRepository);

    /**
     * 删除漏洞库
     * 
     * @param scriptId 漏洞库主键
     * @return 结果
     */
    public int deleteVulnRepositoryByScriptId(Long scriptId);

    /**
     * 批量删除漏洞库
     * 
     * @param scriptIds 需要删除的数据主键集合
     * @return 结果
     */
    public int deleteVulnRepositoryByScriptIds(Long[] scriptIds);
}
