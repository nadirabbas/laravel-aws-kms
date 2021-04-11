<?php

namespace KmsEncryption\Console\Commands;

use Aws\Kms\KmsClient;
use Illuminate\Console\Command;

class KmsGenerateDataKey extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'kms:generate-data-key 
                                {--save-as-app-key : Save as APP_KEY in .env} 
                                {--cmk= : Specify the CMK}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Generate a DEK using AWS';

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
        $saveAsAppKey = $this->option('save-as-app-key');
        $cmk = $this->option('cmk') ?? env('AWS_KMS_CMK');

        if(empty($cmk)){
            echo 'No CMK specified. Specify with --cmk or AWS_KMS_CMK environmental variable' . PHP_EOL;
            return 1;
        }

        $dataKey = $kmsClient->generateDataKeyWithoutPlaintext([
            'KeyId' => $cmk,
            'KeySpec' => 'AES_256',
        ])->get('CiphertextBlob');

        $dataKeyEncoded = 'base64:' . base64_encode($dataKey);

        if($saveAsAppKey){

            $escaped = preg_quote('='.$this->laravel['config']['app.key'] ?? '', '/');

            file_put_contents($this->laravel->environmentFilePath(), preg_replace(
                "/^APP_KEY{$escaped}/m",
                'APP_KEY=' . $dataKeyEncoded,
                file_get_contents($this->laravel->environmentFilePath())
            ));

        }

        echo $dataKeyEncoded . PHP_EOL;

        return 0;
    }
}
