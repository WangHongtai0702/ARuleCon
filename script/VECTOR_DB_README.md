# 向量数据库构建脚本

## 概述

这个脚本用于处理 `dataset/documentations` 目录中的 PDF 文档，进行智能分块和向量化，构建一个用于 RAG 应用的向量数据库。

## 功能特性

### 🔍 **智能文档分块**

- **基于标题的分块**: 自动识别 markdown 风格的标题结构
- **基于目录的分块**: 检测文档目录结构
- **基于编号章节的分块**: 识别数字编号的章节
- **语义单元分块**: 按段落和句子进行智能分块

### 📚 **多 SIEM 支持**

- Splunk
- Microsoft Sentinel
- IBM QRadar
- Google Chronicle
- RSA NetWitness

### 🗄️ **向量数据库**

- 使用 ChromaDB 作为向量存储
- **多集合架构**: 每个 SIEM 拥有独立的集合
- 支持持久化存储
- 集成 sentence-transformers 进行向量化

### 📁 **文件夹结构组织**

```
vector_db/
├── Splunk/                    # Splunk 相关文档和集合
├── Microsoft Sentinel/        # Microsoft Sentinel 相关文档和集合
├── IBM QRadar/               # IBM QRadar 相关文档和集合
├── Google Chronicle/          # Google Chronicle 相关文档和集合
├── RSA NetWitness/           # RSA NetWitness 相关文档和集合
└── chroma.sqlite3            # ChromaDB 数据库文件
```

## 安装依赖

### 1. 安装 Python 依赖

```bash
pip install -r requirements.txt
```

### 2. 脚本会自动：

- 扫描 `dataset/documentations` 目录
- 处理所有 PDF 文件
- 进行智能分块
- 构建向量数据库
- 为每个 SIEM 创建独立的集合和文件夹

## 使用方法

### 1. **构建向量数据库**

```bash
cd script
python build_vector_db.py
```

### 2. **查询向量数据库**

```bash
cd script
python query_vector_db.py
```

### 3. **测试数据库结构**

```bash
cd script
python test_vector_db_structure.py
```

## 分块策略

### 1. **基于标题的分块 (Header-based Chunking)**

适用于有明确标题结构的文档：

```markdown
# 主标题

内容...

## 子标题

更多内容...

### 三级标题

详细内容...
```

### 2. **基于目录的分块 (TOC-based Chunking)**

检测文档中的目录结构，按章节进行分块。

### 3. **基于编号章节的分块 (Numbered Section Chunking)**

识别数字编号的章节结构：

```
1. 第一章

内容...

2. 第二章

更多内容...
```

### 4. **语义单元分块 (Semantic Unit Chunking)**

当文档结构不明确时，按段落和句子进行智能分块。

## 配置参数

### 分块参数

```python
processor = PDFDocumentProcessor(
    chunk_size=1000,      # 每个块的最大字符数
    chunk_overlap=200     # 块之间的重叠字符数
)
```

### 向量数据库参数

```python
vector_db = VectorDatabaseBuilder(
    db_path="./vector_db"  # 数据库存储路径
)
```

## 输出结构

### 1. **向量数据库**

- 位置: `./vector_db/`
- 格式: ChromaDB 持久化存储
- 集合结构: 每个 SIEM 一个独立集合
  - `siem_splunk`
  - `siem_microsoft_sentinel`
  - `siem_ibm_qradar`
  - `siem_google_chronicle`
  - `siem_rsa_netwitness`

### 2. **处理报告**

- 文件: `processing_summary.json`
- 内容: 处理统计、SIEM 分类、数据库信息、输出结构

### 3. **日志文件**

- 文件: `vector_db_build.log`
- 内容: 详细的处理日志

## 查询功能

### 1. **SIEM 特定查询**

```python
# 查询特定 SIEM 的文档
results = vector_db.search("security rule", siem_name="Splunk", n_results=5)
```

### 2. **跨 SIEM 查询**

```python
# 在所有 SIEM 中搜索
results = vector_db.search("security rule", n_results=10)
```

### 3. **集合信息查询**

```python
# 获取所有集合的信息
info = vector_db.get_collection_info()
```

## 处理摘要

```
==================================================
PROCESSING SUMMARY
==================================================
Total files processed: 15
Total chunks created: 1250
Vector database path: ./vector_db

SIEM Breakdown:
  Splunk: 3 files, 250 chunks
  Microsoft Sentinel: 4 files, 300 chunks
  IBM QRadar: 3 files, 200 chunks
  Google Chronicle: 3 files, 250 chunks
  RSA NetWitness: 2 files, 150 chunks

Output Directory Structure:
  ./vector_db/Splunk
  ./vector_db/Microsoft Sentinel
  ./vector_db/IBM QRadar
  ./vector_db/Google Chronicle
  ./vector_db/RSA NetWitness

Vector database ready for RAG applications!
Each SIEM has its own collection and directory structure.
```

### 向量数据库信息

```json
{
  "total_collections": 5,
  "collections": {
    "Splunk": {
      "name": "siem_splunk",
      "total_chunks": 250,
      "metadata": {
        "description": "Documentation chunks for Splunk",
        "siem": "Splunk"
      }
    }
  },
  "database_path": "./vector_db"
}
```

## 高级用法

### 1. **批量处理特定 SIEM**

```python
from build_vector_db import PDFDocumentProcessor, VectorDatabaseBuilder

# 只处理 Splunk 文档
processor = PDFDocumentProcessor()
vector_db = VectorDatabaseBuilder("./vector_db")

# 处理特定 SIEM
siem_name = "Splunk"
# ... 处理逻辑
```

### 2. **自定义分块策略**

```python
# 创建自定义分块器
processor = PDFDocumentProcessor(
    chunk_size=500,      # 更小的块
    chunk_overlap=100    # 更少的重叠
)
```

## 常见问题

1. **PDF 文本提取失败**

   ```
   错误: Error extracting text from PDF
   解决: 脚本会自动使用 PyPDF2 作为备选方案
   ```

2. **依赖安装失败**

   ```
   错误: ModuleNotFoundError
   解决: 确保安装了所有依赖包
   ```

3. **内存不足**

   ```
   错误: MemoryError
   解决: 减少 chunk_size 或分批处理大文档
   ```

## 故障排除

### 启用详细日志

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### 1. **分块策略优化**

- 对于技术文档，使用较小的 chunk_size (500-1000)
- 对于长文档，增加 chunk_overlap (200-300)

### 2. **内存管理**

- 分批处理大文档
- 及时清理临时变量

### 3. **并行处理**

- 可以修改脚本支持多进程处理
- 注意向量数据库的并发限制

## 扩展功能

### 1. **支持更多文档格式**

- Word 文档 (.docx)
- 纯文本文件 (.txt)
- Markdown 文件 (.md)

### 2. **增强的分块策略**

- 基于表格的分块
- 基于图片的分块
- 基于代码块的分块

### 3. **多语言支持**

- 中文文档处理
- 多语言混合文档

## 贡献指南

欢迎提交 Issue 和 Pull Request 来改进这个脚本！

## 许可证

本项目采用 MIT 许可证。
