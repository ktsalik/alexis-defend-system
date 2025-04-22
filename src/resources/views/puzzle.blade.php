<html>
  <head>
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
  </head>
  <body>
    <form action="{{ url('alexis-verify') }}" method="POST">
      @csrf
      <div id="html_element"></div>
      <br>
      <input type="submit" id="submitBtn" value="Submit" disabled>
    </form>

    <script src="https://www.google.com/recaptcha/api.js?onload=onloadCallback&render=explicit"
      async defer></script>
  </body>
</html>
