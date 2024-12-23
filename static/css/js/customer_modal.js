// Modal functionality
const customerModal = document.getElementById('customerModal');
const closeBtn = document.querySelector('.close-btn');
const customerForm = document.getElementById('customerForm');

// Add these styles for the modal
const modalStyles = document.createElement('style');
modalStyles.textContent = `
    .modal {
        display: none;
        position: fixed;
        z-index: 1000;
        left: 0;
        top: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(0,0,0,0.5);
    }
    /* ... rest of your modal styles ... */
`; 