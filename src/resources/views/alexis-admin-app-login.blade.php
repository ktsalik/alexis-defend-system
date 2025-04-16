<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">

	<!-- Fonts -->
	<link rel="preconnect" href="https://fonts.googleapis.com">
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
	<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&display=swap" rel="stylesheet">

	<!-- ========== Stylesheets ========== -->
	<!-- Bootstrap Icons -->
	<link rel="stylesheet" href="<?= asset('assets/fonts/icons/font/bootstrap-icons.css') ?>">
	<!-- All Vendors -->
	<link rel="stylesheet" href="<?= asset('assets/css/vendor.css') ?>">
	<!-- Theme CSS -->
	<link rel="stylesheet" href="<?= asset('assets/css/aio-admin.css') ?>">
	<!-- Your Custom Code -->
	<link rel="stylesheet" href="<?= asset('assets/css/custom.css') ?>">
	<!-- ========== End Stylesheets ========== -->

	<title>Welcome Back to Alexis Defend System</title>
</head>
<body class="">
	<div class="container vh-100 d-flex flex-column justify-content-between">
		<div class="auth-card">
			<div class="form-area card p-lg-5 p-4">
				<div class="text-center">
					<div class="brand" style="height: unset;">
            <img src="<?= asset('alexis-logo.png') ?>" class="logo" style="height: 85px;" alt="" srcset="">
					</div>
					<h1 class="form-heading">
						Καλωσήρθατε
					</h1>
					<div class="pt-2">
						<p>
							Εισάγετε διαπιστευτήρια για να συνεχίσετε
						</p>
					</div>
				</div>
				
				<form class="form" method="POST" action="authenticate">
					<div class="mb-3">
						<label for="username" class="form-label">Όνομα Χρήστη</label>
						<input type="text" class="form-control" id="username" name="username" aria-describedby="username" placeholder="">
					</div>
					<div class="mb-3">
						<label for="password" class="form-label">Συνθηματικό</label>
						<input type="password" class="form-control" id="exampleInputEmail1" name="password" aria-describedby="password" placeholder="">
					</div>
					<div class="form-check mt-3">
						<input class="form-check-input" type="checkbox" value="" id="flexCheckDefault">
						<label class="form-check-label" for="flexCheckDefault">
							Remember me
						</label>
					</div>
					<div class="form-cta mt-3 text-center">
						<div class="d-grid">
							<button type="submit" class="btn btn-primary mb-3">Είσοδος</button>
						</div>
						<!-- <span>Don't have an account?</span>
						<a href="auth-card-register.html" class="text-primary btn btn-link p-0">Register</a> -->
					</div>
				</form>
			</div>
		</div>
	</div>
	
	<!-- ========== Start Scripts ========== -->
	<!-- All Vendors -->
	<script src="<?= asset('assets/js/vendor.js') ?>"></script>
	<!-- Theme JS -->
	<script src="<?= asset('assets/js/aio.admin.js') ?>"></script>
	<!-- Your Custom Code -->
	<script src="<?= asset('assets/js/custom.js') ?>"></script>

	<!-- Page Level Javasctipt -->
	<script>
    if (localStorage.getItem('theme') === 'light') {
      document.querySelector('.logo-dark').classList.add('d-none');
      document.querySelector('.logo').classList.remove('d-none');
    }
	</script>
	<!-- /Page Level Javasctipt -->
	<!-- ========== End Scripts ========== -->
</body>
</html>