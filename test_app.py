from flask import Flask
from markupsafe import Markup
import markdown

# 测试基本导入
app = Flask(__name__)

# 测试markdown渲染
with app.app_context():
    test_content = "# Test Markdown\n\nThis is a **test**"
    rendered = Markup(markdown.markdown(test_content))
    print("Markdown rendering test passed")
    print(f"Rendered: {rendered}")

print("All tests passed!")