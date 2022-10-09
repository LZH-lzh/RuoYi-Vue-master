package com.ruoyi.vuln.commandsubject;

import com.ruoyi.vuln.commandobserver.CommandExecutorObserver;
import com.ruoyi.vuln.domain.NmapCommand;

import java.util.ArrayList;

public interface CommandExecutorSubject {
	//发布者
	public ArrayList<CommandExecutorObserver> observers = new ArrayList<CommandExecutorObserver>();
	public void addObserver(CommandExecutorObserver observer) ;
	public void removeObserver(CommandExecutorObserver observer);
	public void notifyObserves(NmapCommand nmapCommand);
}
