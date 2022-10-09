package com.ruoyi.vuln.commandobserver;

import com.ruoyi.vuln.commandsubject.CommandExecutorSubject;
import com.ruoyi.vuln.domain.NmapCommand;

public interface CommandExecutorObserver {
	 public void update(NmapCommand cmd);
}
