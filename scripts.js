document.addEventListener('DOMContentLoaded', () => {
    const updateLinks = document.querySelectorAll('a');
    
    // 提示用户点击下载链接
    updateLinks.forEach(link => {
        link.addEventListener('mouseover', () => {
            link.style.color = '#ff5722'; // 鼠标悬停时更改颜色
        });
        
        link.addEventListener('mouseout', () => {
            link.style.color = ''; // 恢复默认颜色
        });
    });
});
