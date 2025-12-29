// NeoShare 主JavaScript文件
console.log('NeoShare 应用已加载');

// 通用文件上传表单处理
document.addEventListener('DOMContentLoaded', function() {
    // 处理所有上传表单
    const uploadForms = document.querySelectorAll('.upload-form');
    
    uploadForms.forEach(form => {
        const fileInput = form.querySelector('input[type="file"]');
        const fileInfo = form.querySelector('#file-info');
        const selectedFilename = form.querySelector('#selected-filename');
        const submitBtn = form.querySelector('button[type="submit"]');
        
        if (fileInput && fileInfo && selectedFilename && submitBtn) {
            // 文件选择事件
            fileInput.addEventListener('change', function(e) {
                if (e.target.files.length > 0) {
                    selectedFilename.textContent = e.target.files[0].name;
                    fileInfo.style.display = 'block';
                } else {
                    fileInfo.style.display = 'none';
                    selectedFilename.textContent = '';
                }
            });
        }
    });
});
