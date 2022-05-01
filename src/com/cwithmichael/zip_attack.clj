(ns com.cwithmichael.zip-attack
  (:require
   [clojure.java.io :as io]
   [clojure.string :as str]
   [clojure.core.match :refer [match]])
  (:import [net.lingala.zip4j ZipFile]
           [net.lingala.zip4j.exception ZipException])
  (:gen-class))

(defn guess-file-type
  "Guess the file's type based on its extension."
  [file-name]
  (if (.contains file-name ".")
    (subs file-name (inc (str/last-index-of file-name ".")))
    nil))

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

(defn check-password
  "Checks to see if the password is valid for a zip entry.
   It does so by comparing the decrypted header to the expected header."
  [zip-file-name entry-name expected-header password]
  (try
    (let [zip-file  (ZipFile. zip-file-name (.toCharArray password))
          file-header (.getFileHeader zip-file entry-name)
          input-stream (.getInputStream zip-file file-header)
          buffer (byte-array (count expected-header))]
      (.read input-stream buffer)
      (java.util.Arrays/equals (byte-array buffer) (byte-array expected-header)))
    (catch ZipException e
      (match [(.toString (.getType e))]
        ["WRONG_PASSWORD"] false
        :else (throw e)))))

(defn read-in-and-check-passwords
  "Read in passwords from stdin and check to see if one is valid."
  [zip-file-name entry-name expected-header]
  #_{:clj-kondo/ignore [:missing-else-branch]}
  (some #(if (check-password zip-file-name entry-name expected-header %) %)
        (line-seq (java.io.BufferedReader. *in*))))

(defn print-usage []
  (println "zip-attack <zip-file> <entry-name> *<file-extension>")
  (println "Arguments marked with '*' are optional"))

(defn -main [& args]
  (if (< (count args) 2)
    (print-usage)
    (let [zip-file-name (first args)
          entry-name (second args)
          expected-header (if (= (count args) 3)
                            (get-header (nth args 2))
                            (get-header (guess-file-type entry-name)))]
      (if (.exists (io/file zip-file-name))
        (if (nil? expected-header)
          (do
            (println "Unknown file extension")
            (System/exit 1))
          (do
            (println "Now reading passwords...")
            (try
              (if-let [p (read-in-and-check-passwords zip-file-name entry-name expected-header)]
                (println "Found it! ->" p)
                (println "Password not found"))
              (catch net.lingala.zip4j.exception.ZipException e
                (println
                 "Something went wrong trying to read the file from the zip: "
                 (.toString (.getMessage e)))))))
        (do
          (println "Zip file not found: " zip-file-name)
          (System/exit 1))))))
