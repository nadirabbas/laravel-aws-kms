<?php

namespace KmsEncryption\Console\Commands;

use Aws\Kms\KmsClient;
use Illuminate\Console\Command;
use Illuminate\Encryption\Encrypter;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Str;

class KmsTest extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'kms:test';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Test app encrypt and decrypt';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(KmsClient $kmsClient)
    {
        $unencrypted = Str::random();
        echo "unencrypted=$unencrypted" . PHP_EOL;
        $encrypted = Crypt::encrypt($unencrypted);
        echo "encrypted=$encrypted" . PHP_EOL;
        $decrypted = Crypt::decrypt($encrypted);
        echo "decrypted=$decrypted" . PHP_EOL;
    }
}
