(ns com.cwithmichael.zip-attack-test
  (:require [clojure.test :refer [deftest is]]
            [com.cwithmichael.zip-attack :refer [check-password get-header
                                                 guess-file-type]]))

(deftest get-header-test
  (is (= (get-header "jpg") [0xff 0xd8])))

(deftest guess-file-type-test
  (is (= (guess-file-type "really.long.file.name.zip") "zip")))

(deftest check-password-test
  (is (=
       (check-password "./test/com/cwithmichael/cats.zip" "kitten.jpg" (get-header "jpg") "fun")
       true)))
