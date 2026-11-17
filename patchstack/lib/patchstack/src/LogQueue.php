<?php

namespace Patchstack;

class LogQueue
{
    const HEADER = "<?php exit; ?>\n";

    public static function consume($path, callable $consumer, $limit = 100)
    {
        $lock = @fopen($path . '.lock', 'c');
        if (!$lock) {
            return false;
        }
        if (!flock($lock, LOCK_EX | LOCK_NB)) {
            fclose($lock);
            return false;
        }
        $pending = $path . '.pending.php';
        try {
            // No other consumer owns these files once the process lock is held.
            $prefix = basename($pending) . '.';
            $directory = @opendir(dirname($path));
            if ($directory) {
                while (($name = readdir($directory)) !== false) {
                    if (strpos($name, $prefix) === 0 && substr($name, -4) === '.php') {
                        @unlink(dirname($path) . '/' . $name);
                    }
                }
                closedir($directory);
            }
            if (!is_file($pending) && !self::snapshot($path, $pending)) {
                return false;
            }
            if (!is_file($pending)) {
                return true;
            }
            $file = @fopen($pending, 'rb');
            if (!$file) {
                return false;
            }
            $consumed = 0;
            $count = 0;
            $success = true;
            try {
                while ($count < $limit && ($line = fgets($file)) !== false) {
                    if (trim($line) === '' || strpos($line, '<?php') !== false) {
                        $consumed = ftell($file);
                        continue;
                    }
                    if ($consumer($line) === false) {
                        $success = false;
                        // A broken subsite must not stall the other sites in this shared file.
                        if (!self::retry($path, $line)) {
                            break;
                        }
                    }
                    $consumed = ftell($file);
                    $count++;
                }
                return self::acknowledge($file, $pending, $consumed) && $success;
            } finally {
                if (is_resource($file)) {
                    fclose($file);
                }
            }
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private static function snapshot($path, $pending)
    {
        $file = @fopen($path, 'r+b');
        if (!$file) {
            return !is_file($path);
        }
        $temporary = $pending . '.' . uniqid('', true) . '.php';
        $copy = false;
        try {
            // Producers already append under LOCK_EX. Keep their inode and PHP guard intact.
            if (!flock($file, LOCK_EX)) {
                return false;
            }
            if (trim((string) fgets($file)) !== '<?php exit; ?>') {
                return false;
            }
            $headerLength = ftell($file);
            $size = fstat($file);
            if ($size['size'] <= $headerLength) {
                return true;
            }
            $copy = @fopen($temporary, 'xb');
            if (!$copy || fseek($file, 0) !== 0 || stream_copy_to_stream($file, $copy) !== $size['size'] || !fflush($copy)) {
                return false;
            }
            fclose($copy);
            $copy = false;
            if (!@rename($temporary, $pending)) {
                return false;
            }
            // A crash can duplicate a batch, but must never lose its only durable copy.
            return ftruncate($file, $headerLength);
        } finally {
            if (is_resource($copy)) {
                fclose($copy);
            }
            if (is_file($temporary)) {
                @unlink($temporary);
            }
            flock($file, LOCK_UN);
            fclose($file);
        }
    }

    private static function retry($path, $line)
    {
        $file = @fopen($path, 'r+b');
        if (!$file) {
            return false;
        }
        try {
            if (!flock($file, LOCK_EX) || trim((string) fgets($file)) !== '<?php exit; ?>' || fseek($file, 0, SEEK_END) !== 0) {
                return false;
            }
            $end = ftell($file);
            if (fwrite($file, $line) !== strlen($line) || !fflush($file)) {
                ftruncate($file, $end);
                return false;
            }
            return true;
        } finally {
            fclose($file);
        }
    }

    private static function acknowledge($file, $pending, $consumed)
    {
        if (!$consumed) {
            return true;
        }
        $size = fstat($file);
        if ($consumed >= $size['size']) {
            fclose($file);
            return @unlink($pending);
        }
        $temporary = $pending . '.' . uniqid('', true) . '.php';
        $copy = @fopen($temporary, 'xb');
        if (!$copy) {
            return false;
        }
        try {
            if (fwrite($copy, self::HEADER) !== strlen(self::HEADER) || fseek($file, $consumed) !== 0
                || stream_copy_to_stream($file, $copy) !== $size['size'] - $consumed || !fflush($copy)) {
                return false;
            }
            fclose($copy);
            fclose($file);
            return @rename($temporary, $pending);
        } finally {
            if (is_resource($copy)) {
                fclose($copy);
            }
            if (is_file($temporary)) {
                @unlink($temporary);
            }
        }
    }
}
