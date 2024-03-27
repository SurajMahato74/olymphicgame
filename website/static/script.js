document.getElementById('loginIcon').addEventListener('click', function (event) {
    event.stopPropagation(); // Stop the click event from reaching the window listener
    var loginMenu = document.getElementById('loginMenu');
    loginMenu.style.display = (loginMenu.style.display === 'block') ? 'none' : 'block';
});

// Close the menu if the user clicks outside of it
window.addEventListener('click', function (event) {
    var loginMenu = document.getElementById('loginMenu');
    var loginIcon = document.getElementById('loginIcon');
    if (event.target !== loginMenu && event.target !== loginIcon) {
        loginMenu.style.display = 'none';
    }
});




// Set the date we're counting down to (replace with your desired end date)
var countDownDate = new Date("Jan 31, 2025 00:00:00").getTime();

// Update the countdown every 1 second
var x = setInterval(function() {
    // Get the current date and time
    var now = new Date().getTime();

    // Calculate the time remaining
    var distance = countDownDate - now;

    // Calculate days, hours, minutes, and seconds
    var days = Math.floor(distance / (1000 * 60 * 60 * 24));
    var hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    var minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
    var seconds = Math.floor((distance % (1000 * 60)) / 1000);

    // Update the HTML elements with the calculated values
    document.getElementById("days").innerHTML = formatTime(days);
    document.getElementById("hours").innerHTML = formatTime(hours);
    document.getElementById("minutes").innerHTML = formatTime(minutes);
    document.getElementById("seconds").innerHTML = formatTime(seconds);

    // If the countdown is over, display a message
    if (distance < 0) {
        clearInterval(x);
        document.getElementById("countdown").innerHTML = "EXPIRED";
    }
}, 1000);

// Helper function to format time with leading zeros
function formatTime(time) {
    return time < 10 ? "0" + time : time;
}

document.addEventListener("DOMContentLoaded", function() {
    var nav = document.getElementById('navbar');

    window.addEventListener('scroll', function() {
        if (window.scrollY > 0) {
            nav.classList.add('scrolled');
        } else {
            nav.classList.remove('scrolled');
        }
    });
});



/*date picker*/

document.addEventListener('DOMContentLoaded', function () {
    var startDatePicker = new Pikaday({
      field: document.getElementById('start-date'),
      format: 'MM/DD/YYYY',
      onSelect: function () {
        console.log('Start Date selected: ' + startDatePicker.toString());
      }
    });

    var endDatePicker = new Pikaday({
      field: document.getElementById('end-date'),
      format: 'MM/DD/YYYY',
      onSelect: function () {
        console.log('End Date selected: ' + endDatePicker.toString());
      }
    });

    document.getElementById('date-range').addEventListener('click', function () {
      document.getElementById('date-range-picker').style.display = 'block';
    });

    document.getElementById('date-range-overlay').addEventListener('click', function () {
      document.getElementById('date-range-picker').style.display = 'none';
    });
  });

  window.applyDateRange = function () {
    console.log('Date Range applied');
    document.getElementById('date-range-picker').style.display = 'none';
  };


