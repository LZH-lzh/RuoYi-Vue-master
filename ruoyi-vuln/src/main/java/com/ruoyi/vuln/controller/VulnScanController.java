package com.ruoyi.vuln.controller;

import com.ruoyi.common.annotation.Log;
import com.ruoyi.common.core.controller.BaseController;
import com.ruoyi.common.core.domain.AjaxResult;
import com.ruoyi.common.core.domain.entity.SysUser;
import com.ruoyi.common.core.page.TableDataInfo;
import com.ruoyi.common.enums.BusinessType;
import com.ruoyi.common.utils.poi.ExcelUtil;
import com.ruoyi.vuln.commandobserver.CommandExecutorObserver;
import com.ruoyi.vuln.commandsubject.CommandExecutorSubject;
import com.ruoyi.vuln.domain.NmapCommand;
import com.ruoyi.vuln.domain.Output;
import com.ruoyi.vuln.domain.VulnDetectHistory;
import com.ruoyi.vuln.service.INmapExecutor;
import com.ruoyi.vuln.service.IVulnDetectHistoryService;
import com.ruoyi.vuln.service.impl.INmapExecutorImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * 漏洞扫描历史记录Controller
 * 
 * @author ruoyi
 * @date 2022-09-25
 */
@RestController
@RequestMapping("/vuln/scan")
public class VulnScanController extends BaseController implements CommandExecutorObserver
{
    private List<NmapCommand> ongoingCommands  = new ArrayList<NmapCommand>();
    private List<NmapCommand> finishedCommands = new ArrayList<NmapCommand>();
    @Autowired
    private INmapExecutor nmapExecutor;
    @Autowired
    private CommandExecutorSubject subject;

    /**
     * 初始化脚本列表
     */
    @PreAuthorize("@ss.hasPermi('vuln:scan:initscript')")
    @Log(title = "脚本初始化", businessType = BusinessType.INSERT)
    @GetMapping("/initscript")
    public AjaxResult initScript()
    {
        subject.addObserver(this);
        return AjaxResult.success(nmapExecutor.nmapInitScript());
    }

    /**
     * 初始化脚本列表
     */
    @PreAuthorize("@ss.hasPermi('vuln:scan:scanvuln')")
    ///@Log(title = "漏洞扫描", businessType = BusinessType.INSERT)
    @PostMapping("/scanvuln")
    public AjaxResult scanVuln(@RequestBody NmapCommand nmapCommand)
    {
        System.out.println(nmapCommand.getAddrFileName());
        System.out.println(nmapCommand.getUuid());
        System.out.println(nmapCommand.getScriptSelect());
        System.out.println(nmapCommand.isChecked());
        System.out.println(nmapCommand.getSrcIP());
        System.out.println(nmapCommand.getDesIP());
        System.out.println("...............");
        this.ongoingCommands.add(0, nmapCommand);
        subject.addObserver(this);
        int len = finishedCommands.size();
        nmapExecutor.nmapExecute(nmapCommand);
        System.out.println("返回1值by333v3");
        System.out.println(finishedCommands.get(0).getUuid()+finishedCommands.get(0).getOutput());
        return AjaxResult.success(new Output(finishedCommands.get(0).getUuid(),finishedCommands.get(0).getOutput()));
    }

    //@PreAuthorize("@ss.hasPermi('vuln:scan:importAddr')")
    @PostMapping("/importAddr")
    public AjaxResult importData(MultipartFile file, boolean updateSupport) throws Exception
    {
        nmapExecutor.handleFile(file);
        return AjaxResult.success("成功");
    }

    @Override
    public void update(NmapCommand nmapCommand) {
        this.ongoingCommands.remove(nmapCommand);
        this.finishedCommands.add(0, nmapCommand);
    }
}
