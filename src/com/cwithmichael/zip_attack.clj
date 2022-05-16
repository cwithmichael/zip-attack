(ns com.cwithmichael.zip-attack
  (:require
   [clojure.java.io :as io]
   [clojure.string :as str]
   [clojure.core.match :refer [match]])
  (:import [net.lingala.zip4j.io.inputstream ZipInputStream]
           [net.lingala.zip4j.exception ZipException]
           [java.io FileInputStream])
  (:gen-class))

(defn get-header
  "Get the header based on the file extension."
  [ext]
  (match [ext]
    [(:or "wmv" "asf" "wma")] [0x30 0x26 0xB2 0x75]
    ["png"]  [0x89 0x50 0x4E 0x47 0x0D 0x0A 0x1A 0x0A]
    ["jpg"] [0xFF 0xD8]
    [(:or "zip" "apk" "jar")] [0x50 0x4B 0x03 0x04]
    ["xml"] [0x3C 0x3F 0x78 0x6D 0x6C 0x20]
    :else nil))

(defn guess-file-type
  "Guess the file's type based on its extension."
  [file-name]
  (if (and (not-empty file-name) (str/includes? file-name "."))
    (subs file-name (inc (str/last-index-of file-name ".")))
    nil))

(defn find-file-in-zip
  "Find the file entry in the zip"
  [zip-file entry-name password]
  (let [input-stream  (FileInputStream. zip-file)
        zip-input-stream (ZipInputStream. input-stream password)]
    (some
     #(when (= (.getFileName %) entry-name) zip-input-stream)
     (repeatedly #(.getNextEntry zip-input-stream)))))

(defn check-password
  "Checks to see if the password is valid for a zip entry.
  It does so by comparing the decrypted header to the expected header."
  [zip-file entry-name expected-header password]
  (try
    (let [entry-input-stream (find-file-in-zip zip-file entry-name (char-array password))
          buffer (byte-array (count expected-header))]
      (.read entry-input-stream buffer)
      (java.util.Arrays/equals (byte-array buffer) (byte-array expected-header)))
    (catch ZipException e
      (match [(.toString (.getType e))]
        ["WRONG_PASSWORD"] false
        :else (throw e)))))

(defn read-in-and-check-passwords
  "Read in passwords from stdin and check to see if one is valid."
  [zip-file entry-name expected-header]
  (some #(when (check-password zip-file entry-name expected-header %) %)
        (line-seq (java.io.BufferedReader. *in*))))

(defn print-usage []
  (println "zip-attack <zip-file> <entry-name> *<file-extension>")
  (println "Arguments marked with '*' are optional"))

(defn -main [& args]
  (if (< (count args) 2)
    (print-usage)
    (let [zip-file-name (first args)
          entry-name (second args)
          zip-file (io/file zip-file-name)]
      (if (.exists zip-file)
        (if-let [expected-header (if (= (count args) 3)
                                   (get-header entry-name)
                                   (get-header (guess-file-type entry-name)))]
          (do
            (println "Now reading passwords...")
            (try
              (if-let [password (read-in-and-check-passwords zip-file entry-name expected-header)]
                (println "Found it! ->" password)
                (println "Password not found"))
              (catch net.lingala.zip4j.exception.ZipException e
                (println
                 "Something went wrong trying to read the file from the zip: "
                 (.toString (.getMessage e))))))
          (do
            (println "Unknown file extension:" entry-name)
            (System/exit 1)))
        (do
          (println "Zip file not found: " zip-file-name)
          (System/exit 1))))))
