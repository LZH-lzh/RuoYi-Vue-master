package com.ruoyi.vuln.service.impl;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.ruoyi.vuln.domain.vo.ExecutionObjectFactory;
import com.ruoyi.vuln.domain.vo.Script;
import com.ruoyi.vuln.domain.vo.ScriptHelp;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.ruoyi.vuln.mapper.VulnRepositoryMapper;
import com.ruoyi.vuln.domain.VulnRepository;
import com.ruoyi.vuln.service.IVulnRepositoryService;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;

/**
 * 漏洞库Service业务层处理
 * 
 * @author IPv6ScanGroup
 * @date 2022-10-05
 */
@Service
public class VulnRepositoryServiceImpl implements IVulnRepositoryService 
{
    @Autowired
    private VulnRepositoryMapper vulnRepositoryMapper;

    public void updateScript() {
        //XML文件由Nmap程序输出
        try{
            //Process p = Runtime.getRuntime().exec("nmap --script-help all -oX F:\\NmapTemp\\44.xml --webxml");
            /*commandThread = new Thread(new Runnable() {
                public void run() {

                }
            });*/
            StringBuilder sb = new StringBuilder();
            try {
                BufferedReader br = new BufferedReader(new FileReader("F:\\NmapTemp\\44.xml"));
                String sCurrentLine;
                while ((sCurrentLine = br.readLine()) != null) {
                    sb.append(sCurrentLine);
                }
                JAXBContext jaxbContext = JAXBContext.newInstance(ExecutionObjectFactory.class);
                Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
                StringReader reader = new StringReader(sb.toString());
                Object execution = unmarshaller.unmarshal(reader);
                if (execution instanceof ScriptHelp) {
                    ScriptHelp sh = (ScriptHelp) execution;
                    List<Script> list = sh.getScripts();
                    Iterator<Script> iterator = list.iterator();
                    VulnRepository vr = new VulnRepository();
                    while (iterator.hasNext()) {
                        Script script = iterator.next();
                        if (script.getCategories().contains("vuln")) {
                            //正则表达式取出脚本名称
                            String[] sl = script.getFilename().split("scripts\\\\");
                            //String[] ll = sl[1].split("\\.");
                            //System.out.println(ll[0]);
                            vr.setScriptName(sl[1]);
                            vr.setScriptDescription(script.getDescription());
                            insertVulnRepository(vr);
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }catch(Exception e)
        {
            e.printStackTrace();
        }
    }

    /**
     * 查询漏洞库
     * 
     * @param scriptId 漏洞库主键
     * @return 漏洞库
     */
    @Override
    public VulnRepository selectVulnRepositoryByScriptId(Long scriptId)
    {
        return vulnRepositoryMapper.selectVulnRepositoryByScriptId(scriptId);
    }

    /**
     * 查询漏洞库列表
     * 
     * @param vulnRepository 漏洞库
     * @return 漏洞库
     */
    @Override
    public List<VulnRepository> selectVulnRepositoryList(VulnRepository vulnRepository)
    {
        return vulnRepositoryMapper.selectVulnRepositoryList(vulnRepository);
    }

    /**
     * 新增漏洞库
     * 
     * @param vulnRepository 漏洞库
     * @return 结果
     */
    @Override
    public int insertVulnRepository(VulnRepository vulnRepository)
    {
        return vulnRepositoryMapper.insertVulnRepository(vulnRepository);
    }

    /**
     * 修改漏洞库
     * 
     * @param vulnRepository 漏洞库
     * @return 结果
     */
    @Override
    public int updateVulnRepository(VulnRepository vulnRepository)
    {
        return vulnRepositoryMapper.updateVulnRepository(vulnRepository);
    }

    /**
     * 批量删除漏洞库
     * 
     * @param scriptIds 需要删除的漏洞库主键
     * @return 结果
     */
    @Override
    public int deleteVulnRepositoryByScriptIds(Long[] scriptIds)
    {
        return vulnRepositoryMapper.deleteVulnRepositoryByScriptIds(scriptIds);
    }

    /**
     * 删除漏洞库信息
     * 
     * @param scriptId 漏洞库主键
     * @return 结果
     */
    @Override
    public int deleteVulnRepositoryByScriptId(Long scriptId)
    {
        return vulnRepositoryMapper.deleteVulnRepositoryByScriptId(scriptId);
    }
}
