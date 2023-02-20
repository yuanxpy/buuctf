<?php
class BUU{
    public $correct = "";
    public $input = "";
}
$chen = new BUU();
$chen->input=&$chen->correct;
$chen = serialize($chen);
echo $chen."<br />";
