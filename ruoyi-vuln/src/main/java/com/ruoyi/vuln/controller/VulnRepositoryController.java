package com.ruoyi.vuln.controller;

import java.util.List;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.ruoyi.common.annotation.Log;
import com.ruoyi.common.core.controller.BaseController;
import com.ruoyi.common.core.domain.AjaxResult;
import com.ruoyi.common.enums.BusinessType;
import com.ruoyi.vuln.domain.VulnRepository;
import com.ruoyi.vuln.service.IVulnRepositoryService;
import com.ruoyi.common.utils.poi.ExcelUtil;
import com.ruoyi.common.core.page.TableDataInfo;

/**
 * 漏洞库Controller
 * 
 * @author IPv6ScanGroup
 * @date 2022-10-05
 */
@RestController
@RequestMapping("/vuln/repository")
public class VulnRepositoryController extends BaseController
{
    @Autowired
    private IVulnRepositoryService vulnRepositoryService;

    /**
     * 手动更新漏洞库脚本
     */
    //@PreAuthorize("@ss.hasPermi('vuln:repository:list')")
    @GetMapping("/update")
    public void updateScript()
    {
        vulnRepositoryService.updateScript();
    }

    /**
     * 查询漏洞库列表
     */
    @PreAuthorize("@ss.hasPermi('vuln:repository:list')")
    @GetMapping("/list")
    public TableDataInfo list(VulnRepository vulnRepository)
    {
        startPage();
        List<VulnRepository> list = vulnRepositoryService.selectVulnRepositoryList(vulnRepository);
        return getDataTable(list);
    }

    /**
     * 导出漏洞库列表
     */
    @PreAuthorize("@ss.hasPermi('vuln:repository:export')")
    @Log(title = "漏洞库", businessType = BusinessType.EXPORT)
    @PostMapping("/export")
    public void export(HttpServletResponse response, VulnRepository vulnRepository)
    {
        List<VulnRepository> list = vulnRepositoryService.selectVulnRepositoryList(vulnRepository);
        ExcelUtil<VulnRepository> util = new ExcelUtil<VulnRepository>(VulnRepository.class);
        util.exportExcel(response, list, "漏洞库数据");
    }

    /**
     * 获取漏洞库详细信息
     */
    @PreAuthorize("@ss.hasPermi('vuln:repository:query')")
    @GetMapping(value = "/{scriptId}")
    public AjaxResult getInfo(@PathVariable("scriptId") Long scriptId)
    {
        return AjaxResult.success(vulnRepositoryService.selectVulnRepositoryByScriptId(scriptId));
    }

    /**
     * 新增漏洞库
     */
    @PreAuthorize("@ss.hasPermi('vuln:repository:add')")
    @Log(title = "漏洞库", businessType = BusinessType.INSERT)
    @PostMapping
    public AjaxResult add(@RequestBody VulnRepository vulnRepository)
    {
        return toAjax(vulnRepositoryService.insertVulnRepository(vulnRepository));
    }

    /**
     * 修改漏洞库
     */
    @PreAuthorize("@ss.hasPermi('vuln:repository:edit')")
    @Log(title = "漏洞库", businessType = BusinessType.UPDATE)
    @PutMapping
    public AjaxResult edit(@RequestBody VulnRepository vulnRepository)
    {
        return toAjax(vulnRepositoryService.updateVulnRepository(vulnRepository));
    }

    /**
     * 删除漏洞库
     */
    @PreAuthorize("@ss.hasPermi('vuln:repository:remove')")
    @Log(title = "漏洞库", businessType = BusinessType.DELETE)
	@DeleteMapping("/{scriptIds}")
    public AjaxResult remove(@PathVariable Long[] scriptIds)
    {
        return toAjax(vulnRepositoryService.deleteVulnRepositoryByScriptIds(scriptIds));
    }
}
