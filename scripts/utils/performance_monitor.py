#!/usr/bin/env python3
"""
性能监控工具
用于监控扫描过程的资源使用情况
"""

import os
import time
import psutil
import threading
from datetime import datetime
from pathlib import Path


class PerformanceMonitor:
    """性能监控器"""
    
    def __init__(self, log_file=None):
        self.log_file = log_file or Path("temp/performance.log")
        self.monitoring = False
        self.monitor_thread = None
        self.start_time = None
        self.peak_memory = 0
        self.peak_cpu = 0
        
    def start(self):
        """开始监控"""
        self.monitoring = True
        self.start_time = time.time()
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def stop(self):
        """停止监控"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
            
    def _monitor_loop(self):
        """监控循环"""
        while self.monitoring:
            try:
                # 获取当前进程
                process = psutil.Process(os.getpid())
                
                # CPU使用率
                cpu_percent = process.cpu_percent(interval=1)
                if cpu_percent > self.peak_cpu:
                    self.peak_cpu = cpu_percent
                
                # 内存使用
                memory_info = process.memory_info()
                memory_mb = memory_info.rss / 1024 / 1024
                if memory_mb > self.peak_memory:
                    self.peak_memory = memory_mb
                
                # 磁盘IO
                io_counters = process.io_counters()
                read_mb = io_counters.read_bytes / 1024 / 1024
                write_mb = io_counters.write_bytes / 1024 / 1024
                
                # 打开文件数
                open_files = len(process.open_files())
                
                # 线程数
                num_threads = process.num_threads()
                
                # 记录日志
                log_entry = {
                    'timestamp': datetime.now().isoformat(),
                    'elapsed_seconds': int(time.time() - self.start_time),
                    'cpu_percent': cpu_percent,
                    'memory_mb': round(memory_mb, 2),
                    'peak_memory_mb': round(self.peak_memory, 2),
                    'disk_read_mb': round(read_mb, 2),
                    'disk_write_mb': round(write_mb, 2),
                    'open_files': open_files,
                    'threads': num_threads
                }
                
                # 写入日志
                with open(self.log_file, 'a') as f:
                    f.write(f"{log_entry}\n")
                
                # 等待下一次采样
                time.sleep(10)  # 每10秒采样一次
                
            except Exception as e:
                print(f"性能监控错误: {e}")
                time.sleep(10)
                
    def get_summary(self):
        """获取性能摘要"""
        if not self.start_time:
            return "未开始监控"
            
        elapsed = time.time() - self.start_time
        hours = int(elapsed // 3600)
        minutes = int((elapsed % 3600) // 60)
        seconds = int(elapsed % 60)
        
        summary = f"""
性能监控摘要:
- 运行时间: {hours}小时{minutes}分{seconds}秒
- 峰值CPU使用率: {self.peak_cpu:.1f}%
- 峰值内存使用: {self.peak_memory:.1f} MB
- 详细日志: {self.log_file}
"""
        return summary


def monitor_command(command, log_prefix=""):
    """监控命令执行的性能"""
    import subprocess
    
    # 创建性能监控器
    log_file = Path(f"temp/performance_{log_prefix}_{int(time.time())}.log")
    monitor = PerformanceMonitor(log_file)
    
    # 开始监控
    monitor.start()
    
    try:
        # 执行命令
        start_time = time.time()
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        elapsed = time.time() - start_time
        
        # 停止监控
        monitor.stop()
        
        # 打印结果
        print(f"\n命令执行完成:")
        print(f"- 命令: {command}")
        print(f"- 返回码: {result.returncode}")
        print(f"- 执行时间: {elapsed:.2f}秒")
        print(monitor.get_summary())
        
        return result
        
    except Exception as e:
        monitor.stop()
        print(f"执行错误: {e}")
        return None


if __name__ == '__main__':
    # 测试性能监控
    print("开始性能监控测试...")
    
    # 监控一个示例命令
    result = monitor_command("sleep 5 && echo '测试完成'", "test")
    
    if result:
        print(f"标准输出: {result.stdout}")
        print(f"标准错误: {result.stderr}")