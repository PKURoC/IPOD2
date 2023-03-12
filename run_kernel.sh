#!/bin/bash

print_help() {
	echo "Usage: run_kernel.sh [-a <append>] (-m/t) <method>"
	echo "    -h: Show this message."
	echo "    -a: append cmdline argument to the kernel running in the qemu. This argument should set before -m or -t."
	echo "    -m: Choose method."
	echo "         'debug': Start a qemu virtual machine. Initrd is created by busybox."
	echo "         'init': Package the initramfs directory to the initramfs.cpio.gz. It used in qemu."
	echo "         'build': Build the linux kernel just with stderr. Additionally, it will run make clean before."
	echo "    -t: vtpm relative method"
	echo "         'vtpm': Set up a vtpm using socket way."
	echo "         'debug-vtpm': Start a qemu virtual machine with a vtpm device. Initrd is a rootfs."
	echo "         'rfs': Create the disk."
	echo "         'init': mount the rootfs to set up."
	echo "         'uinit': after init, umount the rootfs."

}

if [ $# -eq 0 ]; then
	print_help
fi

while getopts "hm:a:t:" optname; do
	case "$optname" in
	"h")
		print_help
		;;
	"a")
		CMDLINE="$OPTARG"
		;;
		# "i")
		#     INITRD="$OPTARG"
		#     if [ -z "$INITRD" ]
		#     then
		#         echo "initrd file is needed!"
		#         print_help
		#         exit 1
		#     elif [ ! -f "$INITRD" ]
		#     then
		#         echo "$INITRD: No such file!"
		#         exit 1
		#     fi
		#     ;;
	"m")
		if [ "$OPTARG"x = "debug"x ]; then
			# if the process 'qemu-system-x86_64' is running in the background, kill the process
			pid=$(ps -ef | grep 'qemu-system-x86_64' | grep -v 'grep' | awk '{print $2}')
			if [ ! $pid ]; then
				echo "the process 'qemu-system-x86_64' is not run!!!"
			else
				echo "the process 'qemu-system-x86_64' is running!!!"
				kill -9 $pid
				echo "the process 'qemu-system-x86_64' has been killed!!"
			fi
			echo run kernel in qemu for debug
			qemu-system-x86_64 -m 1024 -enable-kvm -s -kernel ./vmlinux -initrd ./initramfs.cpio.gz -nographic -append "console=ttyS0 $CMDLINE"
		elif [ "$OPTARG"x = "init"x ]; then
			echo package the initramfs
			echo "Copy Device file, permission needed!"
			cd initramfs
			# sudo rm -rf dev/ proc/ sys/
			# mkdir sys proc dev
			# sudo cp -a /dev/{null,console,tty,tty1,tty2,tty3,tty4} dev/
			find . -print0 | cpio --null -ov --format=newc | gzip -9 >../initramfs.cpio.gz
			cd -
		elif [ "$OPTARG"x = 'build'x ]; then
			echo start build linux kernel
			time make -j$(nproc) >/dev/null
		elif [ "$OPTARG"x = 'disk'x ]; then
			dd if=/dev/zero of=test.disk bs=512 count=$((32 * 1024 * 1024 / 512))
			mkfs.ext4 -q test.disk
		else
			print_help
		fi
		;;
	"t")
		if [ "$OPTARG"x = 'vtpm'x ]; then
			rm -rf /tmp/myvtpm0
			mkdir /tmp/myvtpm0

			# chown -R tss:root /tmp/myvtpm0
			# swtpm_setup --tpm-state /tmp/myvtpm0 --createek --tpm2
			# export TPM_PATH=/tmp/myvtpm0
			# swtpm_cuse --tpmstate dir=/tmp/myvtpm0 -n vtpm0 --tpm2

			swtpm socket --tpmstate dir=/tmp/myvtpm0 --ctrl type=unixio,path=/tmp/myvtpm0/swtpm-sock --log level=20 --tpm2
		elif [ "$OPTARG"x = "debug-vtpm"x ]; then
			# qemu-system-x86_64 -enable-kvm \
			#     -m 1024 -boot d -bios $SEABIOS/bios.bin \
			#     -tpmdev passthrough,id=tpm0,path=/dev/vtpm0 \
			#     -device tpm-tis,tpmdev=tpm0 \
			#     -kernel ./vmlinux -hda ./rootfs.img \
			#     -nographic -append "root=/dev/sda console=ttyS0 $CMDLINE"

			qemu-system-x86_64 -m 1024 -enable-kvm -s \
				-boot d -bios $SEABIOS_PATH/bios.bin \
				-chardev socket,id=chrtpm,path=/tmp/myvtpm0/swtpm-sock \
				-tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 \
				-kernel ./vmlinux -hda ./rootfs.img \
				-nographic -append "root=/dev/sda console=ttyS0 $CMDLINE"
		elif [ "$OPTARG"x = "rfs"x ]; then
			dd if=/dev/zero of=rootfs.img bs=10240 count=1M
			sudo mkfs.ext4 -F -L linuxroot rootfs.img

			wget http://cdimage.ubuntu.com/cdimage/ubuntu-base/releases/20.04/release/ubuntu-base-20.04.1-base-amd64.tar.gz -O ubuntu-base-amd64.tar.gz
			sudo rmdir /mnt/tmpdir
			sudo mkdir /mnt/tmpdir
			sudo mount -o loop rootfs.img /mnt/tmpdir/
			sudo tar -zxvf ubuntu-base-amd64.tar.gz -C /mnt/tmpdir/

			sudo cp /etc/resolv.conf /mnt/tmpdir/etc/
			sudo mount -t proc /proc /mnt/tmpdir/proc
			sudo mount -t sysfs /sys /mnt/tmpdir/sys
			sudo mount -o bind /dev /mnt/tmpdir/dev
			sudo mount -o bind /dev/pts /mnt/tmpdir/dev/pts

			sudo chroot /mnt/tmpdir
			# Run in the new root
			# apt-get update
			# apt-get install -y \
			#     language-pack-en-base \
			#     sudo \
			#     ssh \
			#     net-tools \
			#     ethtool \
			#     wireless-tools \
			#     ifupdown \
			#     network-manager \
			#     iputils-ping \
			#     rsyslog \
			#     htop \
			#     vim \
			#     xinit xorg \
			#     alsa-utils \
			#     attr \
			#     --no-install-recommends
			# passwd
		elif [ "$OPTARG"x = "init"x ]; then
			sudo rmdir /mnt/tmpdir
			sudo mkdir /mnt/tmpdir
			sudo mount -o loop ./rootfs.img /mnt/tmpdir/
			sudo mount -t proc /proc /mnt/tmpdir/proc
			sudo mount -t sysfs /sys /mnt/tmpdir/sys
			sudo mount -o bind /dev /mnt/tmpdir/dev
			sudo mount -o bind /dev/pts /mnt/tmpdir/dev/pts
			sudo chroot /mnt/tmpdir
		elif [ "$OPTARG"x = "uinit"x ]; then
			sudo umount /mnt/tmpdir/proc/
			sudo umount /mnt/tmpdir/sys/
			sudo umount /mnt/tmpdir/dev/pts/
			sudo umount /mnt/tmpdir/dev/
			sudo umount /mnt/tmpdir/
		else
			print_help
		fi
		;;
	"?")
		print_help
		;;
	esac
done
