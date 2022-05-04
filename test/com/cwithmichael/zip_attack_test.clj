(ns com.cwithmichael.zip-attack-test
  (:require [clojure.test :refer [deftest is]]
            [com.cwithmichael.zip-attack :refer [check-password get-header
                                                 guess-file-type]]))

(deftest get-header-test
  (is (nil? (get-header ".")))
  (is (nil? (get-header nil)))
  (is (= (get-header "jpg") [0xff 0xd8])))

(deftest guess-file-type-test
  (is (nil? (guess-file-type "")))
  (is (nil? (guess-file-type nil)))
  (is (= (guess-file-type ".") ""))
  (is (= (guess-file-type "really.long.file.name.zip") "zip")))

(deftest check-password-test
  (is (=
       (check-password "./test/com/cwithmichael/cats.zip" "kitten.jpg" (get-header "jpg") "fun")
       true)))
