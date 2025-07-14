#!/bin/bash
# 智能清理脚本 - 安全地清理项目中的临时文件和重复文件
# 
# 用法:
#   ./smart_cleanup.sh [选项]
#   
# 选项:
#   --temp        清理扫描流程临时文件
#   --duplicates  清理重复文件
#   --results     清理分析报告
#   --logs        清理旧日志文件
#   --dry-run     仅显示将要删除的文件，不执行删除
#   --backup      删除前创建备份

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BACKUP_DIR="$PROJECT_ROOT/backup/cleanup_$(date +%Y%m%d_%H%M%S)"
DRY_RUN=false
CREATE_BACKUP=false
CLEANUP_TEMP=false
CLEANUP_DUPLICATES=false
CLEANUP_RESULTS=false
CLEANUP_LOGS=false

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 统计变量
TOTAL_FILES=0
TOTAL_SIZE=0
DELETED_FILES=0
DELETED_SIZE=0

echo -e "${BLUE}🧹 智能清理脚本${NC}"
echo -e "${BLUE}===================${NC}"
echo "项目根目录: $PROJECT_ROOT"

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --temp)
            CLEANUP_TEMP=true
            shift
            ;;
        --duplicates)
            CLEANUP_DUPLICATES=true
            shift
            ;;
        --results)
            CLEANUP_RESULTS=true
            shift
            ;;
        --logs)
            CLEANUP_LOGS=true
            shift
            ;;
        --all)
            CLEANUP_TEMP=true
            CLEANUP_DUPLICATES=true
            CLEANUP_RESULTS=true
            CLEANUP_LOGS=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --backup)
            CREATE_BACKUP=true
            shift
            ;;
        --help|-h)
            echo "用法: $0 [选项]"
            echo "选项:"
            echo "  --temp        清理扫描流程临时文件"
            echo "  --duplicates  清理重复文件"
            echo "  --results     清理分析报告"
            echo "  --logs        清理旧日志文件"
            echo "  --dry-run     仅显示将要删除的文件"
            echo "  --backup      删除前创建备份"
            exit 0
            ;;
        *)
            echo "未知选项: $1"
            exit 1
            ;;
    esac
done

# 如果没有指定任何清理选项，默认为交互式选择
if [[ "$CLEANUP_TEMP" == false && "$CLEANUP_DUPLICATES" == false && "$CLEANUP_RESULTS" == false && "$CLEANUP_LOGS" == false ]]; then
    echo -e "${YELLOW}请选择清理类型:${NC}"
    echo "1) 扫描流程临时文件清理 (为新扫描做准备)"
    echo "2) 分析报告清理 (清理start.py输出结果)"
    echo "3) 重复文件清理 (项目重构后的清理)"
    echo "4) 日志文件清理 (清理旧日志)"
    echo "5) 退出"
    
    read -p "请选择 (1-5): " choice
    case $choice in
        1) CLEANUP_TEMP=true ;;
        2) CLEANUP_RESULTS=true ;;
        3) CLEANUP_DUPLICATES=true ;;
        4) CLEANUP_LOGS=true ;;
        5) exit 0 ;;
        *) echo "无效选择"; exit 1 ;;
    esac
fi

# 安全删除函数
safe_delete() {
    local file="$1"
    local description="$2"
    
    if [[ ! -e "$file" ]]; then
        return 0
    fi
    
    local size=$(du -sb "$file" 2>/dev/null | cut -f1 || echo "0")
    TOTAL_FILES=$((TOTAL_FILES + 1))
    TOTAL_SIZE=$((TOTAL_SIZE + size))
    
    if [[ "$DRY_RUN" == true ]]; then
        echo -e "${YELLOW}[DRY-RUN]${NC} 将删除: $file ($description)"
        return 0
    fi
    
    if [[ "$CREATE_BACKUP" == true ]]; then
        local backup_path="$BACKUP_DIR/$(dirname "$file")"
        mkdir -p "$backup_path"
        cp -r "$file" "$backup_path/" 2>/dev/null || true
    fi
    
    if [[ -f "$file" ]]; then
        rm -f "$file"
    elif [[ -d "$file" ]]; then
        rm -rf "$file"
    fi
    
    if [[ ! -e "$file" ]]; then
        echo -e "${GREEN}✅ 已删除:${NC} $file ($description)"
        DELETED_FILES=$((DELETED_FILES + 1))
        DELETED_SIZE=$((DELETED_SIZE + size))
    else
        echo -e "${RED}❌ 删除失败:${NC} $file"
    fi
}

# 创建备份目录
if [[ "$CREATE_BACKUP" == true && "$DRY_RUN" == false ]]; then
    mkdir -p "$BACKUP_DIR"
    echo -e "${BLUE}📦 备份目录:${NC} $BACKUP_DIR"
fi

cd "$PROJECT_ROOT"

# 1. 扫描流程临时文件清理
if [[ "$CLEANUP_TEMP" == true ]]; then
    echo -e "\n${BLUE}🗂️  清理扫描流程临时文件...${NC}"
    echo -e "${YELLOW}这将清理所有扫描过程中的中间文件，为新扫描做准备${NC}"
    
    # temp目录中的扫描临时文件
    if [[ -d "temp" ]]; then
        # 清理测试目录
        for test_dir in temp/test_*; do
            [[ -d "$test_dir" ]] && safe_delete "$test_dir" "测试临时目录"
        done
        
        # 清理扫描流程中间文件
        echo -e "  ${BLUE}清理扫描流程中间文件:${NC}"
        for temp_file in temp/passive.txt temp/brute.txt temp/domain_life temp/httpx_url temp/result_all.json temp/subdomains_fast.txt; do
            [[ -f "$temp_file" ]] && safe_delete "$temp_file" "扫描中间文件"
        done
        
        # 清理可能的备份文件
        for backup_file in temp/*.backup temp/*_backup temp/*.bak; do
            [[ -f "$backup_file" ]] && safe_delete "$backup_file" "备份文件"
        done
        
        # 清理空的temp子目录
        find temp -type d -empty -delete 2>/dev/null || true
    fi
    
    # 清理Python缓存文件
    echo -e "  ${BLUE}清理Python缓存:${NC}"
    find . -name "*.pyc" -type f | while read -r file; do
        safe_delete "$file" "Python缓存文件"
    done
    
    find . -name "__pycache__" -type d | while read -r dir; do
        safe_delete "$dir" "Python缓存目录"
    done
    
    echo -e "  ${GREEN}✅ 扫描流程临时文件清理完成，可以开始新扫描${NC}"
fi

# 2. 重复文件清理
if [[ "$CLEANUP_DUPLICATES" == true ]]; then
    echo -e "\n${BLUE}🔄 清理重复文件...${NC}"
    
    # 根目录重复文件
    [[ -f "start.py" ]] && safe_delete "start.py" "根目录重复文件 (已迁移至scripts/core/)"
    [[ -f "go.sh" ]] && safe_delete "go.sh" "根目录重复文件 (已迁移至scripts/core/)"
    
    # 重复目录
    [[ -d "file" ]] && safe_delete "file" "重复目录 (已迁移至config/)"
    [[ -d "log" ]] && safe_delete "log" "重复目录 (已迁移至temp/)"
    [[ -d "domains" ]] && safe_delete "domains" "重复目录 (已迁移至output/domains/)"
    [[ -d "reports" ]] && safe_delete "reports" "重复目录 (已迁移至output/reports/)"
    
    # 重复脚本
    [[ -f "scripts/utils/install.sh" ]] && safe_delete "scripts/utils/install.sh" "重复脚本 (根目录已有)"
    [[ -f "scripts/utils/del.sh" ]] && safe_delete "scripts/utils/del.sh" "重复脚本 (功能已合并)"
    [[ -f "scripts/utils/update.sh" ]] && safe_delete "scripts/utils/update.sh" "重复脚本 (功能已合并)"
    
    # 旧文档
    [[ -f "docs/README_old.md" ]] && safe_delete "docs/README_old.md" "旧版文档"
    [[ -f "preview_structure.sh" ]] && safe_delete "preview_structure.sh" "一次性调试脚本"
fi

# 3. 分析报告清理
if [[ "$CLEANUP_RESULTS" == true ]]; then
    echo -e "\n${BLUE}📊 清理分析报告...${NC}"
    echo -e "${YELLOW}这将清理start.py生成的所有分析结果${NC}"
    
    # 清理output/domains中的所有结果
    if [[ -d "output/domains" ]]; then
        echo -e "  ${BLUE}清理域名分析结果:${NC}"
        for domain_dir in output/domains/*/; do
            [[ -d "$domain_dir" ]] && safe_delete "$domain_dir" "域名分析结果"
        done
    fi
    
    # 清理output/reports中的所有结果
    if [[ -d "output/reports/scan" ]]; then
        echo -e "  ${BLUE}清理扫描报告:${NC}"
        for report_dir in output/reports/scan/*/; do
            [[ -d "$report_dir" ]] && safe_delete "$report_dir" "扫描分析报告"
        done
    fi
    
    # 清理generations中的所有结果
    if [[ -d "output/generations" ]]; then
        echo -e "  ${BLUE}清理扩展代数结果:${NC}"
        for domain_dir in output/generations/*/; do
            [[ -d "$domain_dir" ]] && safe_delete "$domain_dir" "扩展代数结果"
        done
    fi
    
    echo -e "  ${GREEN}✅ 所有分析报告清理完成，可以重新分析${NC}"
fi

# 4. 日志文件清理
if [[ "$CLEANUP_LOGS" == true ]]; then
    echo -e "\n${BLUE}📋 清理旧日志文件...${NC}"
    
    # 清理output/logs中的旧日志 (保留最新7天)
    if [[ -d "output/logs" ]]; then
        find output/logs -name "*.log" -type f -mtime +7 | while read -r old_log; do
            safe_delete "$old_log" "7天前的日志文件"
        done
    fi
    
    # 清理大型日志文件 (>10MB)
    find . -name "*.log" -type f -size +10M | while read -r big_log; do
        echo -e "${YELLOW}⚠️  发现大型日志文件: $big_log${NC}"
        read -p "是否删除? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            safe_delete "$big_log" "大型日志文件"
        fi
    done
fi

# 最终统计
echo -e "\n${BLUE}📈 清理统计:${NC}"
echo "================================"
echo -e "${GREEN}检查文件数:${NC} $TOTAL_FILES"
echo -e "${GREEN}检查总大小:${NC} $(numfmt --to=iec $TOTAL_SIZE)"
echo -e "${GREEN}删除文件数:${NC} $DELETED_FILES"
echo -e "${GREEN}释放空间:${NC} $(numfmt --to=iec $DELETED_SIZE)"

if [[ "$DRY_RUN" == true ]]; then
    echo -e "\n${YELLOW}💡 这是预览模式，没有实际删除文件${NC}"
    echo "   要执行实际删除，请移除 --dry-run 参数"
elif [[ "$CREATE_BACKUP" == true ]]; then
    echo -e "\n${BLUE}📦 备份文件保存在:${NC} $BACKUP_DIR"
fi

echo -e "\n${GREEN}🎉 清理完成！${NC}"