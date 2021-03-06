//go:generate go run github.com/mailru/easyjson/easyjson -build_tags linux $GOFILE

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// +build linux

package probe

import (
	"syscall"
	"time"

	"github.com/DataDog/datadog-agent/pkg/security/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/eval"
)

// Event categories for JSON serialization
const (
	FIMCategory     = "File Activity"
	ProcessActivity = "Process Activity"
)

// FileSerializer serializes a file to JSON
// easyjson:json
type FileSerializer struct {
	Path                string     `json:"path,omitempty"`
	Name                string     `json:"name,omitempty"`
	ContainerPath       string     `json:"container_path,omitempty"`
	PathResolutionError string     `json:"path_resolution_error,omitempty"`
	Inode               *uint64    `json:"inode,omitempty"`
	Mode                *uint32    `json:"mode,omitempty"`
	OverlayNumLower     *int32     `json:"overlay_numlower,omitempty"`
	MountID             *uint32    `json:"mount_id,omitempty"`
	UID                 *int32     `json:"uid,omitempty"`
	GID                 *int32     `json:"gid,omitempty"`
	XAttrName           string     `json:"attribute_name,omitempty"`
	XAttrNamespace      string     `json:"attribute_namespace,omitempty"`
	Flags               []string   `json:"flags,omitempty"`
	Atime               *time.Time `json:"access_time,omitempty"`
	Mtime               *time.Time `json:"modification_time,omitempty"`
}

// UserContextSerializer serializes a user context to JSON
// easyjson:json
type UserContextSerializer struct {
	User  string `json:"id,omitempty"`
	Group string `json:"group,omitempty"`
}

// ProcessCacheEntrySerializer serializes a process cache entry to JSON
// easyjson:json
type ProcessCacheEntrySerializer struct {
	Pid                 uint32     `json:"pid,omitempty"`
	PPid                uint32     `json:"ppid,omitempty"`
	Tid                 uint32     `json:"tid,omitempty"`
	UID                 uint32     `json:"uid,omitempty"`
	GID                 uint32     `json:"gid,omitempty"`
	User                string     `json:"user,omitempty"`
	Group               string     `json:"group,omitempty"`
	Name                string     `json:"name,omitempty"`
	ContainerPath       string     `json:"executable_container_path,omitempty"`
	Path                string     `json:"executable_path,omitempty"`
	PathResolutionError string     `json:"path_resolution_error,omitempty"`
	Comm                string     `json:"comm,omitempty"`
	Inode               uint64     `json:"executable_inode,omitempty"`
	MountID             uint32     `json:"executable_mount_id,omitempty"`
	TTY                 string     `json:"tty,omitempty"`
	ForkTime            *time.Time `json:"fork_time,omitempty"`
	ExecTime            *time.Time `json:"exec_time,omitempty"`
	ExitTime            *time.Time `json:"exit_time,omitempty"`
}

// ContainerContextSerializer serializes a container context to JSON
// easyjson:json
type ContainerContextSerializer struct {
	ID string `json:"id,omitempty"`
}

// FileEventSerializer serializes a file event to JSON
// easyjson:json
type FileEventSerializer struct {
	FileSerializer `json:",omitempty"`
	Destination    *FileSerializer `json:"destination,omitempty"`

	// Specific to mount events
	NewMountID uint32 `json:"new_mount_id,omitempty"`
	GroupID    uint32 `json:"group_id,omitempty"`
	Device     uint32 `json:"device,omitempty"`
	FSType     string `json:"fstype,omitempty"`
}

// EventContextSerializer serializes an event context to JSON
// easyjson:json
type EventContextSerializer struct {
	Name     string `json:"name,omitempty"`
	Category string `json:"category,omitempty"`
	Outcome  string `json:"outcome,omitempty"`
}

// ProcessContextSerializer serializes a process context to JSON
// easyjson:json
type ProcessContextSerializer struct {
	*ProcessCacheEntrySerializer
	Parent    *ProcessCacheEntrySerializer   `json:"parent,omitempty"`
	Ancestors []*ProcessCacheEntrySerializer `json:"ancestors,omitempty"`
}

// EventSerializer serializes an event to JSON
// easyjson:json
type EventSerializer struct {
	*EventContextSerializer    `json:"evt,omitempty"`
	*FileEventSerializer       `json:"file,omitempty"`
	UserContextSerializer      UserContextSerializer       `json:"usr,omitempty"`
	ProcessContextSerializer   *ProcessContextSerializer   `json:"process,omitempty"`
	ContainerContextSerializer *ContainerContextSerializer `json:"container,omitempty"`
	Date                       time.Time                   `json:"date,omitempty"`
}

func newFileSerializer(fe *model.FileEvent, e *Event) *FileSerializer {
	return &FileSerializer{
		Path:                e.ResolveFileInode(fe),
		PathResolutionError: fe.GetPathResolutionError(),
		ContainerPath:       e.ResolveFileContainerPath(fe),
		Inode:               getUint64Pointer(&fe.Inode),
		MountID:             getUint32Pointer(&fe.MountID),
		OverlayNumLower:     getInt32Pointer(&fe.OverlayNumLower),
	}
}

func newExecSerializer(exec *model.ExecEvent, e *Event) *FileSerializer {
	return &FileSerializer{
		Path:                e.ResolveExecInode(exec),
		PathResolutionError: exec.GetPathResolutionError(),
		ContainerPath:       e.ResolveExecContainerPath(exec),
		Inode:               getUint64Pointer(&exec.Inode),
		MountID:             getUint32Pointer(&exec.MountID),
		OverlayNumLower:     getInt32Pointer(&exec.OverlayNumLower),
	}
}

func getUint64Pointer(i *uint64) *uint64 {
	if *i == 0 {
		return nil
	}
	return i
}

func getUint32Pointer(i *uint32) *uint32 {
	if *i == 0 {
		return nil
	}
	return i
}

func getInt32Pointer(i *int32) *int32 {
	if *i == 0 {
		return nil
	}
	return i
}

func getTimeIfNotZero(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func newProcessCacheEntrySerializer(pce *model.ProcessCacheEntry, e *Event, r *Resolvers, useEvent bool) *ProcessCacheEntrySerializer {
	var pid, ppid, tid, uid, gid uint32
	var user, group string

	if useEvent && e != nil {
		pid = e.Process.Pid
		ppid = e.Process.PPid
		tid = e.Process.Tid
		uid = e.Process.UID
		gid = e.Process.GID
		user = e.ResolveProcessUser(&e.Process)
		group = e.ResolveProcessGroup(&e.Process)
	} else {
		pid = pce.Pid
		ppid = pce.PPid
		tid = pce.Tid
		uid = pce.UID
		gid = pce.GID
		user = e.ResolveExecUser(&pce.ProcessContext.ExecEvent)
		group = e.ResolveExecGroup(&pce.ProcessContext.ExecEvent)
	}

	return &ProcessCacheEntrySerializer{
		Pid:                 pid,
		PPid:                ppid,
		Tid:                 tid,
		UID:                 uid,
		GID:                 gid,
		User:                user,
		Group:               group,
		Name:                e.ResolveExecBasename(&pce.ExecEvent),
		Path:                e.ResolveExecInode(&pce.ExecEvent),
		PathResolutionError: pce.GetPathResolutionError(),
		ContainerPath:       e.ResolveExecContainerPath(&pce.ExecEvent),
		Comm:                e.ResolveExecComm(&pce.ExecEvent),
		Inode:               pce.Inode,
		MountID:             pce.MountID,
		TTY:                 e.ResolveExecTTY(&pce.ExecEvent),
		ForkTime:            getTimeIfNotZero(pce.ForkTime),
		ExecTime:            getTimeIfNotZero(pce.ExecTime),
		ExitTime:            getTimeIfNotZero(pce.ExitTime),
	}
}

func newContainerContextSerializer(cc *model.ContainerContext, e *Event) *ContainerContextSerializer {
	return &ContainerContextSerializer{
		ID: e.ResolveContainerID(cc),
	}
}

func newProcessContextSerializer(entry *model.ProcessCacheEntry, e *Event, r *Resolvers) *ProcessContextSerializer {
	ps := &ProcessContextSerializer{
		ProcessCacheEntrySerializer: newProcessCacheEntrySerializer(entry, e, r, true),
	}

	if e == nil {
		// custom events call newProcessContextSerializer with an empty Event
		e = NewEvent(r)
		e.Process = model.ProcessContext{
			Ancestor: entry,
		}
	}

	ctx := eval.Context{}
	ctx.SetObject(e.GetPointer())

	it := &model.ProcessAncestorsIterator{}
	ptr := it.Front(&ctx)

	first := true
	for ptr != nil {
		ancestor := (*model.ProcessCacheEntry)(ptr)
		s := newProcessCacheEntrySerializer(ancestor, e, r, false)
		ps.Ancestors = append(ps.Ancestors, s)

		if first {
			ps.Parent = s
		}
		first = false

		ptr = it.Next()
	}

	return ps
}

func serializeSyscallRetval(retval int64) string {
	switch {
	case syscall.Errno(retval) == syscall.EACCES || syscall.Errno(retval) == syscall.EPERM:
		return "Refused"
	case retval < 0:
		return "Error"
	default:
		return "Success"
	}
}

func newEventSerializer(event *Event) *EventSerializer {
	s := &EventSerializer{
		EventContextSerializer: &EventContextSerializer{
			Name:     model.EventType(event.Type).String(),
			Category: FIMCategory,
		},
		ProcessContextSerializer: newProcessContextSerializer(event.ResolveProcessCacheEntry(), event, event.resolvers),
		Date:                     event.ResolveEventTimestamp(),
	}

	if event.Container.ID != "" {
		s.ContainerContextSerializer = newContainerContextSerializer(&event.Container, event)
	}

	s.UserContextSerializer.User = s.ProcessContextSerializer.User
	s.UserContextSerializer.Group = s.ProcessContextSerializer.Group

	switch model.EventType(event.Type) {
	case model.FileChmodEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: *newFileSerializer(&event.Chmod.FileEvent, event),
		}
		s.FileSerializer.Mode = &event.Chmod.Mode
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.Chmod.Retval)
	case model.FileChownEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: *newFileSerializer(&event.Chown.FileEvent, event),
		}
		s.FileSerializer.UID = &event.Chown.UID
		s.FileSerializer.GID = &event.Chown.GID
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.Chown.Retval)
	case model.FileLinkEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: *newFileSerializer(&event.Link.Source, event),
			Destination:    newFileSerializer(&event.Link.Target, event),
		}
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.Link.Retval)
	case model.FileOpenEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: *newFileSerializer(&event.Open.FileEvent, event),
		}
		s.FileSerializer.Mode = &event.Open.Mode
		s.FileSerializer.Flags = model.OpenFlags(event.Open.Flags).StringArray()
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.Open.Retval)
	case model.FileMkdirEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: *newFileSerializer(&event.Mkdir.FileEvent, event),
		}
		s.FileSerializer.Mode = &event.Mkdir.Mode
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.Mkdir.Retval)
	case model.FileRmdirEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: *newFileSerializer(&event.Rmdir.FileEvent, event),
		}
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.Rmdir.Retval)
	case model.FileUnlinkEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: *newFileSerializer(&event.Unlink.FileEvent, event),
		}
		s.FileSerializer.Flags = model.UnlinkFlags(event.Unlink.Flags).StringArray()
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.Unlink.Retval)
	case model.FileRenameEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: *newFileSerializer(&event.Rename.Old, event),
			Destination:    newFileSerializer(&event.Rename.New, event),
		}
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.Rename.Retval)
	case model.FileRemoveXAttrEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: *newFileSerializer(&event.RemoveXAttr.FileEvent, event),
		}
		s.FileSerializer.XAttrName = event.GetXAttrName(&event.RemoveXAttr)
		s.FileSerializer.XAttrNamespace = event.GetXAttrNamespace(&event.RemoveXAttr)
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.RemoveXAttr.Retval)
	case model.FileSetXAttrEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: *newFileSerializer(&event.SetXAttr.FileEvent, event),
		}
		s.FileSerializer.XAttrName = event.GetXAttrName(&event.SetXAttr)
		s.FileSerializer.XAttrNamespace = event.GetXAttrNamespace(&event.SetXAttr)
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.SetXAttr.Retval)
	case model.FileUtimeEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: *newFileSerializer(&event.Utimes.FileEvent, event),
		}
		s.FileSerializer.Atime = getTimeIfNotZero(event.Utimes.Atime)
		s.FileSerializer.Mtime = getTimeIfNotZero(event.Utimes.Mtime)
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.Utimes.Retval)
	case model.FileMountEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: FileSerializer{
				Path:                event.ResolveMountRoot(&event.Mount),
				PathResolutionError: event.Mount.GetRootPathResolutionError(),
				MountID:             &event.Mount.RootMountID,
				Inode:               &event.Mount.RootInode,
			},
			Destination: &FileSerializer{
				Path:                event.ResolveMountPoint(&event.Mount),
				PathResolutionError: event.Mount.GetMountPointPathResolutionError(),
				MountID:             &event.Mount.ParentMountID,
				Inode:               &event.Mount.ParentInode,
			},
			NewMountID: event.Mount.MountID,
			GroupID:    event.Mount.GroupID,
			Device:     event.Mount.Device,
			FSType:     event.Mount.GetFSType(),
		}
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.Mount.Retval)
	case model.FileUmountEventType:
		s.FileEventSerializer = &FileEventSerializer{
			NewMountID: event.Umount.MountID,
		}
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.Umount.Retval)
	case model.ForkEventType:
		s.EventContextSerializer.Outcome = serializeSyscallRetval(0)
	case model.ExitEventType:
		s.EventContextSerializer.Outcome = serializeSyscallRetval(0)
	case model.ExecEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: *newExecSerializer(&event.processCacheEntry.ExecEvent, event),
		}
		s.EventContextSerializer.Outcome = serializeSyscallRetval(0)
		s.Category = ProcessActivity
	}

	return s
}
