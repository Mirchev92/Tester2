document.addEventListener('DOMContentLoaded', function() {
    console.log('Favorite script loaded');
    const favoriteButtons = document.querySelectorAll('.favorite-btn');
    console.log('Found favorite buttons:', favoriteButtons.length);
    
    favoriteButtons.forEach(button => {
        console.log('Adding click listener to button:', button.dataset.specialistId);
        button.addEventListener('click', async function(e) {
            e.preventDefault();
            console.log('Button clicked');
            const specialistId = this.dataset.specialistId;
            const isFavorite = this.classList.contains('active');
            console.log('Specialist ID:', specialistId, 'Is favorite:', isFavorite);
            
            try {
                console.log('Sending request to:', `/customer/api/favorite/${specialistId}`);
                const response = await fetch(`/customer/api/favorite/${specialistId}`, {
                    method: isFavorite ? 'DELETE' : 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    credentials: 'same-origin'
                });
                
                console.log('Response status:', response.status);
                const data = await response.json();
                console.log('Response data:', data);
                
                if (response.ok) {
                    // Toggle favorite state
                    this.classList.toggle('active');
                    const specialistCard = this.closest('.specialist-card');
                    specialistCard.classList.toggle('favorite');
                    
                    // Update icon
                    const icon = this.querySelector('i');
                    if (icon) {
                        icon.className = data.status ? 'fas fa-star' : 'far fa-star';
                    }
                    
                    // Show feedback
                    const toast = document.createElement('div');
                    toast.className = 'toast-notification';
                    toast.textContent = data.message;
                    document.body.appendChild(toast);
                    
                    setTimeout(() => {
                        toast.remove();
                    }, 3000);

                    // Reorder specialists
                    const specialistsGrid = document.querySelector('.specialists-grid');
                    const allCards = Array.from(specialistsGrid.children);
                    
                    // Sort the cards: favorites first, then others
                    allCards.sort((a, b) => {
                        const aIsFavorite = a.classList.contains('favorite');
                        const bIsFavorite = b.classList.contains('favorite');
                        return bIsFavorite - aIsFavorite; // True = 1, False = 0
                    });

                    // Remove all cards
                    specialistsGrid.innerHTML = '';
                    
                    // Add cards back in the new order
                    allCards.forEach(card => {
                        specialistsGrid.appendChild(card);
                    });

                    // Add smooth animation
                    specialistCard.style.transition = 'all 0.3s ease-in-out';
                } else {
                    throw new Error(data.error || 'Failed to update favorite status');
                }
            } catch (error) {
                console.error('Error:', error);
                alert('Failed to update favorite status. Please try again.');
            }
        });
    });
});