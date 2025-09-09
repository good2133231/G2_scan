#!/usr/bin/env python3
"""
Grand Rummy APK Directory Crawler
多线程爬取 http://apk.download.grandrummy.in/ 所有内容
"""

import requests
import os
import re
import threading
import time
from urllib.parse import urljoin, urlparse
from queue import Queue
from bs4 import BeautifulSoup
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# 配置
BASE_URL = "http://apk.download.grandrummy.in/"
LOCAL_DIR = "grandrummy_download"
MAX_WORKERS = 8  # 线程数
TIMEOUT = 30
RETRY_COUNT = 3
SKIP_LARGE_FILES = True  # 是否跳过大文件（APK等）
MAX_FILE_SIZE = 200 * 1024 * 1024  # 200MB

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('grandrummy_crawler.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class GrandRummyCrawler:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.downloaded_files = set()
        self.failed_files = set()
        self.large_files = []  # 保存超过200MB的大文件信息
        self.stats = {
            'directories': 0,
            'files': 0,
            'bytes': 0,
            'errors': 0,
            'large_files': 0
        }
        self.lock = threading.Lock()

    def get_directory_listing(self, url):
        """获取目录列表"""
        try:
            response = self.session.get(url, timeout=TIMEOUT)
            response.raise_for_status()
            
            if 'text/html' not in response.headers.get('content-type', ''):
                return None, []
            
            soup = BeautifulSoup(response.content, 'html.parser')
            links = []
            
            # 解析Apache目录列表
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href in ['../']:  # 跳过父目录
                    continue
                    
                name = link.get_text().strip()
                if not name:
                    continue
                    
                is_dir = href.endswith('/')
                links.append({
                    'name': name,
                    'href': href,
                    'is_dir': is_dir,
                    'url': urljoin(url, href)
                })
            
            return response, links
            
        except Exception as e:
            logger.error(f"获取目录失败 {url}: {e}")
            return None, []

    def create_local_path(self, url):
        """创建本地路径"""
        parsed = urlparse(url)
        path = parsed.path.strip('/')
        if not path:
            path = 'index'
        
        local_path = os.path.join(LOCAL_DIR, path)
        return local_path

    def download_file(self, url, local_path, retries=RETRY_COUNT):
        """下载单个文件"""
        if url in self.downloaded_files:
            return True
            
        try:
            # 创建目录
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            
            # 检查是否已存在
            if os.path.exists(local_path):
                logger.info(f"文件已存在，跳过: {local_path}")
                with self.lock:
                    self.downloaded_files.add(url)
                return True
            
            # 获取文件头信息
            head_response = self.session.head(url, timeout=TIMEOUT)
            file_size = int(head_response.headers.get('content-length', 0))
            
            # 检查文件大小
            if SKIP_LARGE_FILES and file_size > MAX_FILE_SIZE:
                logger.warning(f"发现大文件 ({file_size/1024/1024:.1f}MB): {url}")
                # 保存大文件信息
                large_file_info = {
                    'url': url,
                    'local_path': local_path,
                    'size_mb': file_size / 1024 / 1024,
                    'filename': os.path.basename(local_path)
                }
                with self.lock:
                    self.large_files.append(large_file_info)
                    self.stats['large_files'] += 1
                logger.info(f"已标记大文件: {os.path.basename(local_path)} ({file_size/1024/1024:.1f}MB)")
                return True
            
            # 下载文件
            logger.info(f"下载中 ({file_size/1024/1024:.1f}MB): {url}")
            response = self.session.get(url, timeout=TIMEOUT, stream=True)
            response.raise_for_status()
            
            with open(local_path, 'wb') as f:
                downloaded = 0
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        
                        # 进度显示
                        if file_size > 0:
                            progress = (downloaded / file_size) * 100
                            if downloaded % (1024 * 1024) == 0:  # 每MB显示一次
                                logger.info(f"下载进度 {progress:.1f}%: {os.path.basename(local_path)}")
            
            with self.lock:
                self.downloaded_files.add(url)
                self.stats['files'] += 1
                self.stats['bytes'] += file_size
            
            logger.info(f"下载完成: {local_path}")
            return True
            
        except Exception as e:
            logger.error(f"下载失败 {url}: {e}")
            if retries > 0:
                logger.info(f"重试下载 ({retries} 次剩余): {url}")
                time.sleep(2)
                return self.download_file(url, local_path, retries - 1)
            else:
                with self.lock:
                    self.failed_files.add(url)
                    self.stats['errors'] += 1
                return False

    def crawl_directory(self, url, level=0):
        """递归爬取目录"""
        if level > 10:  # 防止无限递归
            logger.warning(f"达到最大递归深度，跳过: {url}")
            return
            
        logger.info(f"{'  ' * level}爬取目录: {url}")
        
        response, links = self.get_directory_listing(url)
        if not links:
            return
        
        # 保存目录页面
        local_path = self.create_local_path(url)
        if not local_path.endswith('/'):
            local_path += '/index.html'
        else:
            local_path = os.path.join(local_path, 'index.html')
            
        try:
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            with open(local_path, 'w', encoding='utf-8') as f:
                f.write(response.text)
            logger.info(f"保存目录页面: {local_path}")
        except Exception as e:
            logger.error(f"保存目录页面失败 {local_path}: {e}")
        
        with self.lock:
            self.stats['directories'] += 1
        
        # 分类处理文件和目录
        files = [item for item in links if not item['is_dir']]
        directories = [item for item in links if item['is_dir']]
        
        # 使用线程池下载文件
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            file_futures = []
            
            for item in files:
                file_url = item['url']
                file_local_path = self.create_local_path(file_url)
                future = executor.submit(self.download_file, file_url, file_local_path)
                file_futures.append(future)
            
            # 等待所有文件下载完成
            for future in file_futures:
                future.result()
        
        # 递归处理子目录
        for item in directories:
            self.crawl_directory(item['url'], level + 1)

    def run(self):
        """开始爬取"""
        logger.info(f"开始爬取: {BASE_URL}")
        logger.info(f"本地目录: {LOCAL_DIR}")
        logger.info(f"线程数: {MAX_WORKERS}")
        
        start_time = time.time()
        
        try:
            self.crawl_directory(BASE_URL)
        except KeyboardInterrupt:
            logger.info("用户中断爬取")
        except Exception as e:
            logger.error(f"爬取失败: {e}")
        
        end_time = time.time()
        duration = end_time - start_time
        
        # 统计信息
        logger.info("=" * 50)
        logger.info("爬取完成统计:")
        logger.info(f"用时: {duration:.2f} 秒")
        logger.info(f"目录数: {self.stats['directories']}")
        logger.info(f"已下载文件数: {self.stats['files']}")
        logger.info(f"大文件数量 (>200MB): {self.stats['large_files']}")
        logger.info(f"已下载总大小: {self.stats['bytes'] / 1024 / 1024:.2f} MB")
        logger.info(f"错误数: {self.stats['errors']}")
        if self.stats['bytes'] > 0 and duration > 0:
            logger.info(f"平均速度: {self.stats['bytes'] / 1024 / 1024 / duration:.2f} MB/s")
        
        # 保存大文件列表
        if self.large_files:
            large_files_path = os.path.join(LOCAL_DIR, "large_files_list.txt")
            try:
                os.makedirs(LOCAL_DIR, exist_ok=True)
                with open(large_files_path, 'w', encoding='utf-8') as f:
                    f.write("Grand Rummy 大文件列表 (超过200MB未下载)\n")
                    f.write("=" * 60 + "\n\n")
                    
                    total_large_size = 0
                    for file_info in sorted(self.large_files, key=lambda x: x['size_mb'], reverse=True):
                        f.write(f"文件名: {file_info['filename']}\n")
                        f.write(f"大小: {file_info['size_mb']:.1f} MB\n")
                        f.write(f"URL: {file_info['url']}\n")
                        f.write(f"本地路径: {file_info['local_path']}\n")
                        f.write("-" * 40 + "\n")
                        total_large_size += file_info['size_mb']
                    
                    f.write(f"\n总计: {len(self.large_files)} 个大文件，总大小: {total_large_size:.1f} MB\n")
                    f.write("\n如需下载这些大文件，可以使用以下命令:\n")
                    for file_info in self.large_files:
                        f.write(f"wget -O '{file_info['local_path']}' '{file_info['url']}'\n")
                
                logger.info(f"大文件列表已保存到: {large_files_path}")
                logger.info(f"大文件总计: {len(self.large_files)} 个文件，总大小: {sum(f['size_mb'] for f in self.large_files):.1f} MB")
            except Exception as e:
                logger.error(f"保存大文件列表失败: {e}")
        
        if self.failed_files:
            logger.error(f"失败文件列表:")
            for url in self.failed_files:
                logger.error(f"  - {url}")

def main():
    """主函数"""
    print("Grand Rummy APK Directory Crawler")
    print("=" * 50)
    
    # 确认爬取
    print(f"目标站点: {BASE_URL}")
    print(f"本地目录: {LOCAL_DIR}")
    print(f"线程数: {MAX_WORKERS}")
    print(f"APK大小限制: {MAX_FILE_SIZE / 1024 / 1024:.0f} MB")
    print(f"大文件处理: 超过{MAX_FILE_SIZE / 1024 / 1024:.0f}MB的文件将被标记但不下载")
    
    confirm = input("\n确认开始爬取? (y/N): ").strip().lower()
    if confirm != 'y':
        print("取消爬取")
        return
    
    crawler = GrandRummyCrawler()
    crawler.run()

if __name__ == "__main__":
    main()
