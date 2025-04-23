<html>
  <head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Human Verification - Alexis</title>
    <script type="text/javascript">
      var onloadCallback = function() {
        grecaptcha.render('html_element', {
          sitekey: "{{ config('alexis.recaptcha.site_key') }}",
          callback: function(response) {
            document.getElementById('submitBtn').disabled = false;
          },
          'expired-callback': function() {
            document.getElementById('submitBtn').disabled = true;
          },
          'error-callback': function() {
            document.getElementById('submitBtn').disabled = true;
          }
        });
      };
    </script>
    <style>
      body {
        display: flex;
        flex-direction: column;
        justify-content: flex-start;
        align-items: center;
        gap: 50px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol";
        padding: 30px;
        box-sizing: border-box;
        background-color: #F1F1F1;
        color: #333333;
      }

      .message {
        width: 800px;
        max-width: 100%;
        margin-top: 25vh;
      }

      p {
        font-size: 16px;
        line-height: 20px;
      }

      input[type="submit"] {
        outline: none;
        border: none;
        max-width: 100%;
        border-radius: 3px;
        padding: 10px 15px;
        box-sizing: border-box;
        background-color: #1c408c;
        color: #FFFFFF;
      }

      input[type="submit"][disabled] {
        background-color: #999;
        color: #CCC;
      }
    </style>
  </head>
  <body>
    <div class="message">
      <h2>Quick Favor</h2>
      <p>
        Unfortunately, there are a few people out there who seem to have way too much time and not-so-great intentions.
        To help us keep things fair and functional, we just need you to take a second to confirm you're not one of them.
      </p>
      <p>
        It’s quick and helps us keep the nonsense out. Appreciate you!
      </p>
    </div>
    <form action="{{ url('alexis-verify') }}" method="POST">
      @csrf
      <div id="html_element"></div>
      <br>
      <input type="submit" id="submitBtn" value="Continue" disabled>
    </form>

    <script src="https://www.google.com/recaptcha/api.js?onload=onloadCallback&render=explicit"
      async defer></script>
  </body>
</html>
