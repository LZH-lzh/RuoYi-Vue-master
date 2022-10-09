package com.ruoyi.vuln.controller;

import java.util.List;
import javax.servlet.http.HttpServletResponse;

import com.ruoyi.vuln.service.INmapExecutor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import com.ruoyi.common.annotation.Log;
import com.ruoyi.common.core.controller.BaseController;
import com.ruoyi.common.core.domain.AjaxResult;
import com.ruoyi.common.enums.BusinessType;
import com.ruoyi.vuln.domain.VulnDetectHistory;
import com.ruoyi.vuln.service.IVulnDetectHistoryService;
import com.ruoyi.common.utils.poi.ExcelUtil;
import com.ruoyi.common.core.page.TableDataInfo;

/**
 * 漏洞扫描历史记录Controller
 * 
 * @author ruoyi
 * @date 2022-09-25
 */
@RestController
@RequestMapping("/vuln/history")
public class VulnDetectHistoryController extends BaseController
{
    @Autowired
    private IVulnDetectHistoryService vulnDetectHistoryService;
    @Autowired
    private INmapExecutor nmapExecutor;

    /**
     * 查询漏洞扫描历史记录列表
     */
    @PreAuthorize("@ss.hasPermi('vuln:history:list')")
    @GetMapping("/list")
    public TableDataInfo list(VulnDetectHistory vulnDetectHistory)
    {
        startPage();
        List<VulnDetectHistory> list = vulnDetectHistoryService.selectVulnDetectHistoryList(vulnDetectHistory);
        return getDataTable(list);
    }

    /**
     * 导出漏洞扫描历史记录列表
     */
    @PreAuthorize("@ss.hasPermi('vuln:history:export')")
    @Log(title = "漏洞扫描历史记录", businessType = BusinessType.EXPORT)
    @PostMapping("/export")
    public void export(HttpServletResponse response, VulnDetectHistory vulnDetectHistory)
    {
        List<VulnDetectHistory> list = vulnDetectHistoryService.selectVulnDetectHistoryList(vulnDetectHistory);
        ExcelUtil<VulnDetectHistory> util = new ExcelUtil<VulnDetectHistory>(VulnDetectHistory.class);
        util.exportExcel(response, list, "漏洞扫描历史记录数据");
    }

    /**
     * 获取漏洞扫描历史记录详细信息
     */
    @PreAuthorize("@ss.hasPermi('vuln:history:query')")
    @GetMapping(value = "/{recordsId}")
    public AjaxResult getInfo(@PathVariable("recordsId") Long recordsId)
    {
        return AjaxResult.success(vulnDetectHistoryService.selectVulnDetectHistoryByRecordsId(recordsId));
    }

    /**
     * 新增漏洞扫描历史记录
     */
    @PreAuthorize("@ss.hasPermi('vuln:history:add')")
    @Log(title = "漏洞扫描历史记录", businessType = BusinessType.INSERT)
    @PostMapping
    public AjaxResult add(@RequestBody VulnDetectHistory vulnDetectHistory)
    {
        return toAjax(vulnDetectHistoryService.insertVulnDetectHistory(vulnDetectHistory));
    }

    /**
     * 修改漏洞扫描历史记录
     */
    @PreAuthorize("@ss.hasPermi('vuln:history:edit')")
    @Log(title = "漏洞扫描历史记录", businessType = BusinessType.UPDATE)
    @PutMapping
    public AjaxResult edit(@RequestBody VulnDetectHistory vulnDetectHistory)
    {
        return toAjax(vulnDetectHistoryService.updateVulnDetectHistory(vulnDetectHistory));
    }

    /**
     * 删除漏洞扫描历史记录
     */
    @PreAuthorize("@ss.hasPermi('vuln:history:remove')")
    @Log(title = "漏洞扫描历史记录", businessType = BusinessType.DELETE)
	@DeleteMapping("/{recordsIds}")
    public AjaxResult remove(@PathVariable Long[] recordsIds)
    {
        return toAjax(vulnDetectHistoryService.deleteVulnDetectHistoryByRecordsIds(recordsIds));
    }
}
