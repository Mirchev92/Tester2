// Your existing reviews code first
function loadSpecialistReviews(specialistId, isAdmin = false) {
    console.log('Loading reviews, isAdmin:', isAdmin);
    fetch(`/customer/api/reviews/${specialistId}`)
        .then(response => response.json())
        .then(reviews => {
            const reviewsContainer = document.getElementById('specialistReviews');
            if (reviews.length === 0) {
                reviewsContainer.innerHTML = '<p class="no-reviews">No reviews yet</p>';
                return;
            }

            reviewsContainer.innerHTML = reviews.map(review => `
                <div class="review-item" id="review-${review.id}">
                    <div class="review-header">
                        <span class="review-author">${review.customer_name}</span>
                        <div class="review-actions">
                            <span class="review-date">${review.created_at}</span>
                            ${isAdmin ? `
                                <button onclick="deleteReview(${review.id})" 
                                        class="delete-review-btn">
                                    <i class="fas fa-trash"></i>
                                </button>
                            ` : ''}
                        </div>
                    </div>
                    <div class="review-rating">
                        ${Array(5).fill(0).map((_, i) => `
                            <i class="${i < review.rating ? 'fas' : 'far'} fa-star"></i>
                        `).join('')}
                    </div>
                    <p class="review-comment">${review.comment}</p>
                </div>
            `).join('');
        })
        .catch(error => {
            console.error('Error loading reviews:', error);
        });
}

function deleteReview(reviewId) {
    if (!confirm('Are you sure you want to delete this review?')) {
        return;
    }

    fetch(`/admin/review/${reviewId}`, {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        },
        credentials: 'same-origin'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Remove the review from DOM
            document.getElementById(`review-${reviewId}`).remove();
            
            // Update specialist's rating display
            const ratingDisplay = document.getElementById('modalRating');
            const reviewsCountDisplay = document.getElementById('modalReviewsCount');
            
            if (ratingDisplay) {
                ratingDisplay.textContent = data.new_rating.toFixed(1);
            }
            if (reviewsCountDisplay) {
                reviewsCountDisplay.textContent = `${data.new_count} reviews`;
            }
            
            // Show success message
            const toast = document.createElement('div');
            toast.className = 'toast-notification success';
            toast.textContent = data.message;
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 3000);
        } else {
            throw new Error(data.error || 'Failed to delete review');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Failed to delete review. Please try again.');
    });
}

// New functions for profile viewing
function viewSpecialistProfile(specialistId) {
    const modal = document.getElementById('profileModal');
    const modalContent = document.getElementById('modalContent');
    
    // Show loading state
    modalContent.innerHTML = '<div class="loading">Loading...</div>';
    modal.style.display = 'block';
    
    // Fetch specialist profile
    fetch(`/api/specialist/${specialistId}/profile`)
        .then(response => response.json())
        .then(data => {
            modalContent.innerHTML = createProfileContent(data);
            loadSpecialistReviews(specialistId, document.body.dataset.userRole === 'admin');
        })
        .catch(error => {
            console.error('Error:', error);
            modalContent.innerHTML = '<div class="error">Error loading profile</div>';
        });
}

function createProfileContent(specialist) {
    return `
        <div class="profile-header">
            <div class="profile-image-container">
                ${specialist.profile_picture ? 
                    `<img src="/static/uploads/${specialist.profile_picture}" 
                         alt="Profile" 
                         class="profile-image" 
                         onerror="this.onerror=null; this.src='/static/images/default-avatar.png'">` :
                    `<i class="fas fa-user profile-placeholder"></i>`}
            </div>
            <div class="profile-info">
                <h2>${specialist.username}</h2>
                <div class="rating-display">
                    ${createRatingStars(specialist.rating)}
                    <span id="modalRating">${specialist.rating.toFixed(1)}</span>
                    <span id="modalReviewsCount">(${specialist.reviews_count} reviews)</span>
                </div>
            </div>
        </div>
        <div class="profile-details">
            <p><i class="fas fa-tools"></i> ${specialist.specialization || 'Not specified'}</p>
            <p><i class="fas fa-map-marker-alt"></i> ${specialist.location || 'Location not specified'}</p>
            <p><i class="far fa-clock"></i> ${specialist.working_hours}</p>
            <p><i class="far fa-calendar"></i> ${specialist.working_days}</p>
        </div>
        <div id="specialistReviews" class="reviews-section"></div>`;
}

function createRatingStars(rating) {
    return Array(5).fill(0)
        .map((_, i) => `<i class="fa${i < rating ? 's' : 'r'} fa-star"></i>`)
        .join('');
}

// Initialize modal functionality
document.addEventListener('DOMContentLoaded', function() {
    const modal = document.getElementById('profileModal');
    const closeBtn = modal.querySelector('.close');
    
    closeBtn.onclick = function() {
        modal.style.display = "none";
    }
    
    window.onclick = function(event) {
        if (event.target === modal) {
            modal.style.display = "none";
        }
    }
});