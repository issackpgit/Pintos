#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "threads/synch.h"

static void syscall_handler(struct intr_frame *);
static bool is_valid_pointer(void *esp);
void halt();
uint32_t fileopen(char* filename);
struct file* get_open_file(int id);

struct open_file {
	int id;
	tid_t owner;
	struct file *file;
	struct list_elem elem;
	char* filename;
};

void syscall_init(void) {
	lock_init(&fs_lock);
	intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler(struct intr_frame *f UNUSED) {
	//first check if f->esp is a valid pointer)
	if (!is_valid_pointer(f->esp)) {
		//		thread_exit();
		exit(-1);
	}

	//cast f->esp into an int*, then dereference it for the SYS_CODE
	switch (*(int*) f->esp) {
	case SYS_HALT: {
		halt();
		break;
	}
	case SYS_EXIT: {
		//Implement syscall EXIT
		//		thread_current()->exit_status = -1;
		if (!is_valid_pointer(f->esp + 4)) {
			exit(-1);
		}

		int status = *((int*) f->esp + 1);
		exit(status);
		break;
	}
	case SYS_WAIT: {
		//		if (!is_valid_pointer(*((int*) f->esp + 1))) {
		//			exit(-1);
		//		}

		f->eax = process_wait(*((int*) f->esp + 1));
		break;
	}

	case SYS_EXEC: {
		if (!is_valid_pointer(*((int*) f->esp + 1))) {
			exit(-1);
		}

		char *copy_samp, *token, *save_ptr;
		struct file *file_load;
		copy_samp = palloc_get_page(0);
		strlcpy(copy_samp, *((int*) f->esp + 1), PGSIZE);

		token = strtok_r(copy_samp, " ", &save_ptr);
		lock_acquire(&fs_lock);
		file_load = filesys_open(token);

		if (file_load == NULL) {
			printf("load: %s: open failed\n", token);
			f->eax = -1;
		} else {
			f->eax = process_execute(*((int*) f->esp + 1));
		}
		lock_release(&fs_lock);
		break;
	}

	case SYS_CREATE: {
		if (!is_valid_pointer(*((int*) f->esp + 1)))
			exit(-1);

		lock_acquire(&fs_lock);

		if (!is_valid_pointer(f->esp))
			exit(-1);

		char *file_to_create = *((int*) f->esp + 1);
		if (!file_to_create)
			exit(-1);
		else
			f->eax = filesys_create(*((int*) f->esp + 1), *((int*) f->esp + 2));

		lock_release(&fs_lock);
		break;
	}

	case SYS_OPEN: {
		if (!is_valid_pointer(*((int*) f->esp + 1)))
			exit(-1);

		lock_acquire(&fs_lock);
		f->eax = fileopen(*((int*) f->esp + 1));
		lock_release(&fs_lock);
		break;
	}

	case SYS_FILESIZE: {
		int fd = *((int*) f->esp + 1);
		if (!fd)
			exit(-1);

		lock_acquire(&fs_lock);
		f->eax = file_size(fd);
		lock_release(&fs_lock);
		break;
	}

	case SYS_WRITE: {
		int fd = *((int*) f->esp + 1);
		void* buffer = (void*) (*((int*) f->esp + 2));
		unsigned size = *((unsigned*) f->esp + 3);

		char* temp = (char *) buffer;
		for (unsigned i = 0; i < size; i++) {
			if (is_valid_pointer(((const void*) temp)))
				temp++;
			else
				exit(-1);
		}

		if (!is_valid_pointer(*((int*) f->esp + 2)))
			exit(-1);

		if (fd == STDOUT_FILENO) {
			putbuf(buffer, size);
			f->eax = size;
		} else {
			lock_acquire(&fs_lock);
			f->eax = filewrite(fd, buffer, size);
			lock_release(&fs_lock);
		}

		break;
	}

	case SYS_READ: {
		if (!is_valid_pointer(*((int*) f->esp + 2)))
			exit(-1);

		int fd = *((int*) f->esp + 1);
		void* buffer = (void*) (*((int*) f->esp + 2));
		unsigned size = *((unsigned*) f->esp + 3);

		if (fd == STDIN_FILENO) {
			char *temp = (char*) buffer;
			for (unsigned i = 0; i < size; i++) {
				temp[i] = input_getc();
			}
			f->eax = size;
		} else {
			lock_acquire(&fs_lock);
			f->eax = fileread(fd, buffer, size);
			lock_release(&fs_lock);
		}
		break;
	}

	case SYS_CLOSE: {
		int fd = *((int*) f->esp + 1);
		lock_acquire(&fs_lock);
		fileclose(fd);
		lock_release(&fs_lock);
		break;
	}

	case SYS_REMOVE: {
		lock_acquire(&fs_lock);
		f->eax = filesys_remove(*((int*) f->esp + 1));
		lock_release(&fs_lock);
		break;
	}

	case SYS_SEEK: {
		lock_acquire(&fs_lock);
		struct file *f1 = get_open_file(*((int*) f->esp + 1));
		file_seek(f1, *((unsigned*) f->esp + 2));
		lock_release(&fs_lock);
		break;
	}

	}

	//	printf("system call!\n");
}

void fileclose(int fd) {
	struct thread *t = thread_current();
	struct list_elem *e;

	for (e = list_begin(&t->open_files); e != list_end(&t->open_files); e
			= list_next(e)) {
		struct open_file *opf = list_entry (e, struct open_file, elem);
		if (opf->id == fd || fd == -1) {
			file_close(opf->file);
			list_remove(&opf->elem);
			free(opf);
			if (fd != -1) {
				return;
			}
		}
	}
}

int fileread(int fd, void *buffer, unsigned size) {
	struct file *f = get_open_file(fd);
	if (!f)
		return -1;
	return file_read(f, buffer, size);
}

int filewrite(int fd, void *buffer, unsigned size) {

	struct thread *t = thread_current();
	struct file *f = NULL;

	for (struct list_elem *e = list_begin(&t->open_files); e != list_end(
			&t->open_files); e = list_next(e)) {
		struct open_file *opf = list_entry (e, struct child, elem);
		if (fd == opf->id)
			if (!strcmp(opf->filename, thread_current()->name))
				return 0;
		f = opf->file;
	}

	if (!f)
		f = get_open_file(fd);

	if (!f)
		return -1;
	return file_write(f, buffer, size);
}

static bool is_valid_pointer(void *esp) {
	if (is_user_vaddr(esp)) {
		return pagedir_get_page(thread_current()->pagedir, esp) != NULL;
	}
	return false;
}

void halt() {
	shutdown_power_off();
}

void exit(int status) {
	struct thread *cur = thread_current();
	struct thread *parent = cur->my_parent;
	struct list* parent_childlist = NULL;
	struct list_elem *e;
	if (&parent->childlist != NULL) {
		for (e = list_begin(&parent->childlist); e != list_end(
				&parent->childlist); e = list_next(e)) {
			struct child *childp = list_entry (e, struct child, elem);
			if (childp->tid == cur->tid) {
				childp->exit_status = status;
				childp->exited = true;
			}
		}
	}
	printf("%s: exit(%d)\n", cur->name, status);
	thread_exit();

}

uint32_t fileopen(char* filename) {
	if (!filename)
		return -1;
	struct thread *t = thread_current();
	struct file* f = filesys_open(filename);
	if (!f)
		return -1;
	struct open_file* opf = malloc(sizeof(struct open_file));

	char *fn_name_copy;
	fn_name_copy = malloc(strlen(filename) + 1);
	strlcpy(fn_name_copy, filename, strlen(filename) + 1);

	opf->owner = t->tid;
	opf->id = ++t->open_file_count;
	opf->file = f;
	opf->filename = fn_name_copy;

	list_push_back(&t->open_files, &opf->elem);
	return opf->id;
}

int file_size(int id) {
	struct file *f = get_open_file(id);
	if (!f)
		return -1;
	return file_length(f);
}

struct file* get_open_file(int id) {
	struct thread *t = thread_current();
	struct file *f = NULL;

	for (struct list_elem *e = list_begin(&t->open_files); e != list_end(
			&t->open_files); e = list_next(e)) {
		struct open_file *opf = list_entry (e, struct child, elem);
		if (id == opf->id)
			f = opf->file;
	}

	return f;
}

