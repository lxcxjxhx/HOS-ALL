from src.doc_processor import DocProcessor
from src.config_manager import ConfigManager
config = ConfigManager('/home/lxcxjxhx/PROJECT/INTEL-SE/config/settings.yaml')
app = type('App', (), {'config_manager': config, 'log_event': lambda self, x, y: print(f'{x}: {y}')})()
processor = DocProcessor(app)
print(processor.process_docs())
print(processor.rag_query('SQL注入'))
