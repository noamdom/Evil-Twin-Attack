<?php

print_r($_POST)
?>



<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <link rel="stylesheet" href="bootstrap.min.css">



    </head>
    <body style="height: 100hv" class="bg-light" >
        <header>
            <nav class="navbar bg-dark navbar-dark navbar-expand-sm ">
                <div class="container"> 
                    <div class="navbar-brand">
                        <a class="" href=""><img class="img-fluid " style="width:30%;border-radius: 40%" src="/img/PBLogo.png " alt="logo PB"></a>
                        <span></span>
                    </div>

                    <div class="navbar-nav text-white ">
                    </div>
                </div>
            </nav>
        </header>
        <!--        <script>
                    $(function() {
                        $('[data-toggle="tooltip"]').tooltip({});
                    });
                    </script>-->



        <main class="bg-light ">

            <div class="container">
                <h2 class="text-center py-3">Enter to catalog</h2>
                <form action="myindex.php.php" method="post">

                    <div class="row">
                        <div class="col-10 offset-1">
                            <div class="form-group ">   
                                <label class="form-control-labal form-control-lg">User name:</label>
                                <input class="form-control form-control-lg" type="text" name="userLogin" value="" />

                            </div>
                            <div class="form-group">   
                                <label class="form-control-labal form-control-lg">Password:</label>
                                <input class="form-control form-control-lg" type="password" name="password" value="" />

                            </div>
                            <div class="row justify-content-center my-5" >
                                <input class="btn btn-primary btn-lg  " type="submit" name="submit" value="OK"  />
                            </div>
                        </div>
                    </div>
                </form>

            </div>
        </main>


        <footer>
            <!--<p>footer</p>-->
        </footer>

    </body>

</html>


