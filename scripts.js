document.addEventListener('DOMContentLoaded', () => {
    const updateLinks = document.querySelectorAll('a');
    
    updateLinks.forEach(link => {
        link.addEventListener('mouseover', () => {
            link.style.color = '#ff5722';
        });
        
        link.addEventListener('mouseout', () => {
            link.style.color = ''; 
        });
    });
});
