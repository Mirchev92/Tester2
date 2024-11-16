document.addEventListener('DOMContentLoaded', function() {
    // Initialize all sections as expanded
    const sections = ['sms-section', 'hours-section', 'vacation-section'];
    sections.forEach(section => {
        const content = document.getElementById(section);
        if (content) {
            content.classList.remove('collapsed');
            const header = content.previousElementSibling;
            header.classList.remove('collapsed');
        }
    });
});

function toggleSection(sectionId) {
    const content = document.getElementById(sectionId);
    const header = content.previousElementSibling;
    
    // Toggle the collapsed class
    content.classList.toggle('collapsed');
    header.classList.toggle('collapsed');
    
    // Rotate the chevron icon
    const icon = header.querySelector('i.fas.fa-chevron-down');
    if (icon) {
        icon.style.transform = content.classList.contains('collapsed') 
            ? 'rotate(180deg)' 
            : 'rotate(0deg)';
    }
}
